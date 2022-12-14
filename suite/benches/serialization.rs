// Copyright (c) 2022, BTI
// SPDX-License-Identifier: Apache-2.0
// to run this code, run cargo bench mutex_lock, for ex.
// TODO - cleanup this benchmark file

extern crate bincode;
extern crate criterion;

use criterion::*;
use crypto::{
    traits::{KeyPair, Signer},
    Hash, DIGEST_LEN,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use types::{
    AccountKeyPair, AccountPubKey, Batch, BatchDigest, GDEXSignedTransaction, GDEXTransaction,
    PaymentRequest, SignedTransactionError, TransactionVariant, WorkerMessage,
    SERIALIZED_TRANSACTION_LENGTH,
};

pub fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
    let mut rng = StdRng::from_seed(seed);
    (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
}

fn verify_incoming_transaction(
    serialized_transaction: Vec<u8>,
) -> Result<(), SignedTransactionError> {
    // remove trailing zeros & deserialize transaction
    let signed_transaction_result = GDEXSignedTransaction::deserialize(serialized_transaction);

    match signed_transaction_result {
        Ok(signed_transaction) => {
            match signed_transaction.verify() {
                Ok(_) => {
                    // transaction was successfully deserialized and the signature matched the payload
                    Ok(())
                }
                // deserialization succeeded, but verification failed
                Err(sig_error) => Err(sig_error),
            }
        }
        // deserialization failed
        Err(derserialize_err) => Err(derserialize_err),
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    fn get_signed_transaction(
        sender_seed: [u8; 32],
        receiver_seed: [u8; 32],
        amount: u64,
    ) -> GDEXSignedTransaction {
        let kp_sender = keys(sender_seed).pop().unwrap();
        let kp_receiver = keys(receiver_seed).pop().unwrap();

        let transaction_variant = TransactionVariant::PaymentTransaction(PaymentRequest::new(
            kp_receiver.public().clone(),
            0,
            amount,
        ));
        let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);

        let transaction = GDEXTransaction::new(
            kp_sender.public().clone(),
            dummy_batch_digest,
            transaction_variant,
        );

        // generate the signed digest for repeated use
        let signed_digest = kp_sender.sign(&(transaction.digest().get_array())[..]);

        GDEXSignedTransaction::new(
            kp_sender.public().clone(),
            transaction.clone(),
            signed_digest.clone(),
        )
    }

    // bench serializing singletons
    fn serialize_1_000(sender_seed: [u8; 32], receiver_seed: [u8; 32]) {
        let signed_transaction = get_signed_transaction(sender_seed, receiver_seed, 10);

        let mut i = 0;
        while i < 1_000 {
            // wrap signed transaction in black box to protect compiler from advance knowledge
            let _ = black_box(signed_transaction.clone()).serialize().unwrap();
            i += 1;
        }
    }

    // bench deserializing singletons
    fn deserialize_1_000(sender_seed: [u8; 32], receiver_seed: [u8; 32]) {
        let signed_transaction_serialized = get_signed_transaction(sender_seed, receiver_seed, 10)
            .serialize()
            .unwrap();

        let mut i = 0;
        while i < 1_000 {
            // wrap signed transaction in black box to protect compiler from advance knowledge
            let _ = GDEXSignedTransaction::deserialize(black_box(
                signed_transaction_serialized.clone(),
            ))
            .unwrap();
            i += 1;
        }
    }

    c.bench_function("serialization_serialize_1_000", move |b| {
        b.iter(|| serialize_1_000(black_box([0 as u8; 32]), black_box([1 as u8; 32])))
    });

    c.bench_function("serialization_deserialize_1_000", move |b| {
        b.iter(|| deserialize_1_000(black_box([0 as u8; 32]), black_box([1 as u8; 32])))
    });

    let mut i = 0;
    let mut batch = Vec::new();
    while i < 1_000 {
        let amount = rand::thread_rng().gen_range(10, 100);
        let signed_transaction = get_signed_transaction([0; 32], [1; 32], amount);
        batch.push(bincode::serialize(&signed_transaction).unwrap());
        i += 1;
    }

    // bench deserializing a batch w/ no verification
    fn deserialize_batch_method1(batch: &[u8]) {
        let _ = match bincode::deserialize(batch).unwrap() {
            WorkerMessage::<AccountPubKey>::Batch(Batch(transactions)) => {
                for transaction_padded in transactions {
                    let transaction: Vec<u8> = transaction_padded
                        .to_vec()
                        .drain(..SERIALIZED_TRANSACTION_LENGTH)
                        .collect();

                    let _ = GDEXSignedTransaction::deserialize(transaction).unwrap();
                    // TxReceiverHandler::verify_incoming_transaction(transaction).unwrap();
                }
            }
            _ => {
                panic!("error occurred in deserialize_batch_method1 while deserializing")
            }
        };
    }

    // bench deserializing a batch w/ verification
    fn deserialize_batch_and_verify_method1(batch: &[u8]) {
        let _ = match bincode::deserialize(batch).unwrap() {
            WorkerMessage::<AccountPubKey>::Batch(Batch(transactions)) => {
                for transaction_padded in transactions {
                    let transaction: Vec<u8> = transaction_padded
                        .to_vec()
                        .drain(..SERIALIZED_TRANSACTION_LENGTH)
                        .collect();

                    verify_incoming_transaction(transaction).unwrap();
                }
            }
            _ => {
                panic!("error occurred in deserialize_batch_and_verify_method1 while deserializing")
            }
        };
    }

    let message = WorkerMessage::<AccountPubKey>::Batch(Batch(batch.clone()));
    let serialized = bincode::serialize(&message).unwrap();

    c.bench_function("serialization_deserialize_batch_method1_1_000", move |b| {
        b.iter(|| deserialize_batch_method1(black_box(&serialized[..])))
    });

    let message = WorkerMessage::<AccountPubKey>::Batch(Batch(batch));
    let serialized = bincode::serialize(&message).unwrap();

    c.bench_function(
        "serialization_deserialize_batch_and_verify_method1_1_000",
        move |b| b.iter(|| deserialize_batch_and_verify_method1(black_box(&serialized[..]))),
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
