// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings};
use crypto::{
    traits::{KeyPair, Signer},
    Hash, DIGEST_LEN,
};
use futures::{future::join_all, StreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::{
    net::TcpStream,
    time::{interval, sleep, Duration, Instant},
};
use tracing::{info, subscriber::set_global_default, warn};
use tracing_subscriber::filter::EnvFilter;
use types::{
    AccountKeyPair, AccountSignature, BatchDigest, GDEXSignedTransaction,
    GDEXTransaction, PaymentRequest, TransactionProto, TransactionVariant,
    TransactionsClient,
};
use url::Url;
const PRIMARY_ASSET_ID: u64 = 0;

fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
    let mut rng = StdRng::from_seed(seed);
    (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
}

fn generate_dummy_signed_digest(
    kp_sender: &AccountKeyPair,
    kp_receiver: &AccountKeyPair,
) -> AccountSignature {
    let transaction_variant = TransactionVariant::PaymentTransaction(PaymentRequest::new(
        kp_receiver.public().clone(),
        PRIMARY_ASSET_ID,
        1,
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
    signed_digest
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Narwhal and Tusk.")
        .args_from_usage("<ADDR> 'The network address of the node where to send txs'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The rate (txs/s) at which to send the transactions'")
        .args_from_usage("--nodes=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    cfg_if::cfg_if! {
        if #[cfg(feature = "benchmark")] {
            let timer = tracing_subscriber::fmt::time::UtcTime::rfc_3339();
            let subscriber_builder = tracing_subscriber::fmt::Subscriber::builder()
                                     .with_env_filter(env_filter)
                                     .with_timer(timer).with_ansi(false);
        } else {
            let subscriber_builder = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(env_filter);
        }
    }
    let subscriber = subscriber_builder.with_writer(std::io::stderr).finish();

    set_global_default(subscriber).expect("Failed to set subscriber");

    let target_str = matches.value_of("ADDR").unwrap();
    let target = target_str
        .parse::<Url>()
        .with_context(|| format!("Invalid url format {target_str}"))?;
    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let nodes = matches
        .values_of("nodes")
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.parse::<Url>())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Invalid url format {target_str}"))?;

    info!("Node address: {target}");

    // NOTE: This log entry is used to compute performance.
    info!("Transactions size: {size} B");

    // NOTE: This log entry is used to compute performance.
    info!("Transactions rate: {rate} tx/s");

    let client = Client {
        target,
        size,
        rate,
        nodes,
    };

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client.send().await.context("Failed to submit transactions")
}

struct Client {
    target: Url,
    size: usize,
    rate: u64,
    nodes: Vec<Url>,
}

impl Client {
    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 20; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }

        // Connect to the mempool.
        let mut client = TransactionsClient::connect(self.target.as_str().to_owned())
            .await
            .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        let burst = self.rate / PRECISION;
        let mut counter = 0;
        let mut r = rand::thread_rng().gen::<u64>();
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        'main: loop {
            interval.as_mut().tick().await;
            let now = Instant::now();

            // generate the keypairs
            let kp_sender = keys([0; 32]).pop().unwrap();
            let kp_receiver = keys([1; 32]).pop().unwrap();

            // generate the signed digest for repeated use
            let dummy_signed_digest = generate_dummy_signed_digest(&kp_sender, &kp_receiver);

            // generate a dummy digest for repeated use
            let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);

            // clone the public key to prep it for freeing in the move statement below
            let public_sender = kp_sender.public().clone();

            let stream = tokio_stream::iter(0..burst).map(move |x| {
                let amount = if x == counter % burst {
                    counter
                } else {
                    r += 1;
                    r
                };

                let transaction_variant = TransactionVariant::PaymentTransaction(
                    PaymentRequest::new(public_sender.clone(), PRIMARY_ASSET_ID, amount),
                );
                let transaction = GDEXTransaction::new(
                    public_sender.clone(),
                    dummy_batch_digest,
                    transaction_variant,
                );
                let signed_transaction = GDEXSignedTransaction::new(
                    public_sender.clone(),
                    transaction.clone(),
                    dummy_signed_digest.clone(),
                );

                // uncomment the below to prove to yourself that we are submitting serialized transactions
                // signed_transaction.verify_transaction().unwrap();
                
                if x == counter % burst {
                    println!("the checkpoint signed_transaction ={:?}", signed_transaction);
                } 

                TransactionProto {
                    transaction: signed_transaction.serialize().unwrap().into(),
                }
            });

            if let Err(e) = client.submit_transaction_stream(stream).await {
                warn!("Failed to send transaction: {e}");
                break 'main;
            }

            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
                warn!("Transaction rate too high for this client");
            }
            counter += 1;
        }
        Ok(())
    }

    pub async fn wait(&self) {
        // Wait for all nodes to be online.
        info!("Waiting for all nodes to be online...");
        join_all(self.nodes.iter().cloned().map(|address| {
            tokio::spawn(async move {
                while TcpStream::connect(&*address.socket_addrs(|| None).unwrap())
                    .await
                    .is_err()
                {
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }))
        .await;
    }
}
