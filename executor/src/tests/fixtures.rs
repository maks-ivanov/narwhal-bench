// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use config::WorkerId;
use crypto::{ed25519::Ed25519PublicKey, traits::{KeyPair, Signer}, Hash};
use gdex_crypto::hash::CryptoHash;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::Serialize;
use std::collections::BTreeMap;
use store::{
    reopen,
    rocks::{open_cf, DBMap},
    Store,
};
use types::{
    serialized_batch_digest, AccountKeyPair, Batch, BatchDigest, Certificate, CryptoMessage, Header, PaymentRequest, SerializedBatchMessage, TransactionRequest, TransactionVariant
};

use worker::WorkerMessage;

/// A test batch containing specific transactions.
pub fn test_batch<T: Serialize>(transactions: Vec<T>) -> (BatchDigest, SerializedBatchMessage) {
    let batch = transactions
        .iter()
        .map(|x| bincode::serialize(x).unwrap())
        .collect();
    let message = WorkerMessage::<Ed25519PublicKey>::Batch(Batch(batch));
    let serialized = bincode::serialize(&message).unwrap();
    let digest = serialized_batch_digest(&serialized).unwrap();
    (digest, serialized)
}

/// A test certificate with a specific payload.
pub fn test_certificate(payload: BTreeMap<BatchDigest, WorkerId>) -> Certificate<Ed25519PublicKey> {
    Certificate {
        header: Header {
            payload,
            ..Header::default()
        },
        ..Certificate::default()
    }
}

/// Make a test storage to hold transaction data.
pub fn test_store() -> Store<BatchDigest, SerializedBatchMessage> {
    let store_path = tempfile::tempdir().unwrap();
    const BATCHES_CF: &str = "batches";
    let rocksdb = open_cf(store_path, None, &[BATCHES_CF]).unwrap();
    let batch_map = reopen!(&rocksdb, BATCHES_CF;<BatchDigest, SerializedBatchMessage>);
    Store::new(batch_map)
}

/// Create a number of test certificates containing transactions of type u64.
pub fn test_u64_certificates(
    certificates: usize,
    batches_per_certificate: usize,
    transactions_per_batch: usize,
) -> Vec<(
    Certificate<Ed25519PublicKey>,
    Vec<(BatchDigest, SerializedBatchMessage)>,
)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..certificates)
        .map(|_| {
            let batches: Vec<_> = (0..batches_per_certificate)
                .map(|_| {
                    test_batch(
                        (0..transactions_per_batch)
                            .map(|_| rng.next_u64())
                            .collect(),
                    )
                })
                .collect();

            let payload: BTreeMap<_, _> = batches
                .iter()
                .enumerate()
                .map(|(i, (digest, _))| (*digest, /* worker_id */ i as WorkerId))
                .collect();

            let certificate = test_certificate(payload);

            (certificate, batches)
        })
        .collect()
}


/// Create a number of test certificates containing transactions of type u64.
pub fn test_transaction_certificates(
    keypair: AccountKeyPair, 
    certificates: usize,
    batches_per_certificate: usize,
    transactions_per_batch: usize,
) -> Vec<(
    Certificate<Ed25519PublicKey>,
    Vec<(BatchDigest, SerializedBatchMessage)>,
)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..certificates)
        .map(|_| {
            let batches: Vec<_> = (0..batches_per_certificate)
                .map(|_| {
                    test_batch(
                        (0..transactions_per_batch)
                            .map(|_| create_signed_payment_transaction(/* keypair */ keypair.copy(), /* asset_id */ 0, /* amount */ rng.gen_range(1,1000)))
                            .collect(),
                    )
                })
                .collect();

            let payload: BTreeMap<_, _> = batches
                .iter()
                .enumerate()
                .map(|(i, (digest, _))| (*digest, /* worker_id */ i as WorkerId))
                .collect();

            let certificate = test_certificate(payload);

            (certificate, batches)
        })
        .collect()
}

pub fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
    let mut rng = StdRng::from_seed(seed);
    (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
}

pub fn generate_signed_payment_transaction(asset_id: u64, amount: u64) -> TransactionRequest {
    let kp_sender = keys([0; 32]).pop().unwrap();
    let kp_receiver = keys([1; 32]).pop().unwrap();
    let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
    let transaction = PaymentRequest::new(
        kp_sender.public().clone(),
        kp_receiver.public().clone(),
        asset_id,
        amount,
        dummy_recent_blockhash,
    );
    let transaction_hash = transaction.digest();
    let signed_hash = kp_sender.sign(transaction_hash.to_string().as_bytes());
    TransactionRequest::new(
        TransactionVariant::PaymentTransaction(transaction),
        kp_sender.public().clone(),
        signed_hash,
    )
}

pub fn create_signed_payment_transaction(keypair: AccountKeyPair, asset_id: u64, amount: u64) -> TransactionRequest {
    let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
    let transaction = PaymentRequest::new(
        keypair.public().clone(),
        keypair.public().clone(),
        asset_id,
        amount,
        dummy_recent_blockhash,
    );
    let transaction_hash = transaction.digest();
    let signed_hash = keypair.sign(transaction_hash.to_string().as_bytes());
    TransactionRequest::new(
        TransactionVariant::PaymentTransaction(transaction),
        keypair.public().clone(),
        signed_hash,
    )
}