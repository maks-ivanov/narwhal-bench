// Copyright (c) 2022, BTI
// SPDX-License-Identifier: Apache-2.0
// to run this code, run cargo bench mutex_lock, for ex.
// TODO - cleanup this benchmark file

extern crate criterion;

use criterion::*;

use crypto::traits::KeyPair;
use crypto::traits::Signer;
use crypto::Hash;
use crypto::DIGEST_LEN;
use proc::bank::BankController;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::{Arc, Mutex};
use tokio::{
    runtime::Runtime,
    sync::mpsc::{channel, Receiver, Sender},
};
use types::{
    AccountKeyPair, BatchDigest, GDEXSignedTransaction, GDEXTransaction, PaymentRequest,
    TransactionVariant,
};

pub fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
    let mut rng = StdRng::from_seed(seed);
    (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    // test mutex
    fn obtain_mutex_lock(bank_controller: &Mutex<BankController>) {
        let _ = bank_controller.lock().unwrap();
    }
    let bank_controller = Mutex::new(BankController::default());

    c.bench_function("mutex_lock", move |b| {
        b.iter(|| obtain_mutex_lock(&bank_controller))
    });

    // test arc mutex
    fn obtain_arc_mutex_lock(bank_controller: &Arc<Mutex<BankController>>) {
        let _ = bank_controller.lock().unwrap();
    }
    let bank_controller = Arc::new(Mutex::new(BankController::default()));

    c.bench_function("arc_mutex_lock", move |b| {
        b.iter(|| obtain_arc_mutex_lock(&bank_controller))
    });

    // test channels by checking the speed to send 1_000 messages
    pub const DEFAULT_CHANNEL_SIZE: usize = 1_000;

    async fn init_channel_64(_bytes_sent: [u8; 64]) {
        let (_tx, mut _rx): (Sender<[u8; 64]>, Receiver<[u8; 64]>) = channel(DEFAULT_CHANNEL_SIZE);
    }

    async fn init_channel_512(_bytes_sent: [u8; 512]) {
        let (_tx, mut _rx): (Sender<[u8; 512]>, Receiver<[u8; 512]>) =
            channel(DEFAULT_CHANNEL_SIZE);
    }

    async fn send_channel_64_1_000(bytes_sent: [u8; 64]) {
        let (tx, mut _rx) = channel(DEFAULT_CHANNEL_SIZE);
        let mut i = 0;
        while i < 1_000 {
            let _ = tx.send(bytes_sent).await.unwrap();
            i += 1;
        }
    }

    async fn send_channel_512_1_000(bytes_sent: [u8; 512]) {
        let (tx, mut _rx) = channel(DEFAULT_CHANNEL_SIZE);
        let mut i = 0;
        while i < 1_000 {
            let _ = tx.send(bytes_sent).await.unwrap();
            i += 1;
        }
    }

    async fn send_and_receive_channel_64_1_000(bytes_sent: [u8; 64]) {
        let (tx, mut rx) = channel(DEFAULT_CHANNEL_SIZE);
        let mut i = 0;
        while i < 1_000 {
            let _ = tx.send(bytes_sent).await.unwrap();
            let _ = rx.recv().await.unwrap();
            i += 1;
        }
    }

    async fn send_and_receive_channel_512_1_000(bytes_sent: [u8; 512]) {
        let (tx, mut rx) = channel(DEFAULT_CHANNEL_SIZE);
        let mut i = 0;
        while i < 1_000 {
            let _ = tx.send(bytes_sent).await.unwrap();
            let _ = rx.recv().await.unwrap();
            i += 1;
        }
    }

    c.bench_function("concurrency_init_channel_64", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| init_channel_64(black_box([0 as u8; 64])))
    });

    c.bench_function("concurrency_send_channel_64_1_000", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| send_channel_64_1_000(black_box([0 as u8; 64])))
    });

    c.bench_function("concurrency_send_and_receive_channel_64_1_000", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| send_and_receive_channel_64_1_000(black_box([0 as u8; 64])))
    });

    c.bench_function("concurrency_init_channel_512_1_000", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| init_channel_512(black_box([0 as u8; 512])))
    });

    c.bench_function("concurrency_send_channel_512_1_000", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| send_channel_512_1_000(black_box([0 as u8; 512])))
    });

    c.bench_function("concurrency_send_and_receive_channel_512_1_000", move |b| {
        b.to_async(Runtime::new().unwrap())
            .iter(|| send_and_receive_channel_512_1_000(black_box([0 as u8; 512])))
    });

    fn get_signed_transaction(
        sender_seed: [u8; 32],
        receiver_seed: [u8; 32],
    ) -> GDEXSignedTransaction {
        let kp_sender = keys(sender_seed).pop().unwrap();
        let kp_receiver = keys(receiver_seed).pop().unwrap();

        let transaction_variant = TransactionVariant::PaymentTransaction(PaymentRequest::new(
            kp_receiver.public().clone(),
            0,
            10,
        ));
        let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);

        let transaction = GDEXTransaction::new(
            kp_sender.public().clone(),
            dummy_batch_digest,
            transaction_variant,
        );
        let transaction_digest = transaction.digest();

        // generate the signed digest for repeated use
        let signed_digest = kp_sender.sign(transaction_digest.to_string().as_bytes());

        GDEXSignedTransaction::new(
            kp_sender.public().clone(),
            transaction.clone(),
            signed_digest.clone(),
        )
    }

    // bench serializing
    fn serialize_1_000(sender_seed: [u8; 32], receiver_seed: [u8; 32]) {
        let signed_transaction = get_signed_transaction(sender_seed, receiver_seed);

        let mut i = 0;
        while i < 1_000 {
            // wrap signed transaction in black box to protect compiler from advance knowledge
            let _ = black_box(signed_transaction.clone()).serialize().unwrap();
            i += 1;
        }
    }

    // bench deserializing
    fn deserialize_1_000(sender_seed: [u8; 32], receiver_seed: [u8; 32]) {
        let signed_transaction_serialized = get_signed_transaction(sender_seed, receiver_seed)
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
    c.bench_function("concurrency_serialize_1_000", move |b| {
        b.iter(|| serialize_1_000(black_box([0 as u8; 32]), black_box([1 as u8; 32])))
    });

    c.bench_function("concurrency_deserialize_1_000", move |b| {
        b.iter(|| deserialize_1_000(black_box([0 as u8; 32]), black_box([1 as u8; 32])))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
