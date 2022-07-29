// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
// to run this code, run cargo bench mutex
extern crate criterion;

use criterion::*;
use proc::bank::BankController;
use std::sync::{Arc, Mutex};

fn criterion_benchmark(c: &mut Criterion) {
    fn obtain_mutex_lock(bank_controller: &Mutex<BankController>) {
        let _ = bank_controller.lock().unwrap();
    }
    let bank_controller = Mutex::new(BankController::default());

    c.bench_function("mutex_lock", move |b| {
        b.iter(|| obtain_mutex_lock(&bank_controller))
    });

    fn obtain_arc_mutex_lock(bank_controller: &Arc<Mutex<BankController>>) {
        let _ = bank_controller.lock().unwrap();
    }
    let bank_controller = Arc::new(Mutex::new(BankController::default()));

    c.bench_function("arc_mutex_lock", move |b| {
        b.iter(|| obtain_arc_mutex_lock(&bank_controller))
    });

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
