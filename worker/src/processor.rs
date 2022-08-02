// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use config::WorkerId;
use crypto::traits::VerifyingKey;
use store::Store;
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
    task::JoinHandle,
};
use tracing::error;
use types::{
    error::DagError, serialized_batch_digest, Batch, BatchDigest, ReconfigureNotification, GDEXSignedTransaction,
    SerializedBatchMessage, WorkerMessage, WorkerPrimaryMessage, SERIALIZED_TRANSACTION_LENGTH,
};

#[cfg(test)]
#[path = "tests/processor_tests.rs"]
pub mod processor_tests;

/// Hashes and stores batches, it then outputs the batch's digest.
pub struct Processor;

impl Processor {
    pub fn spawn<PublicKey: VerifyingKey>(
        // Our worker's id.
        id: WorkerId,
        // The persistent storage.
        store: Store<BatchDigest, SerializedBatchMessage>,
        // Receive reconfiguration signals.
        mut rx_reconfigure: watch::Receiver<ReconfigureNotification<PublicKey>>,
        // Input channel to receive batches.
        mut rx_batch: Receiver<SerializedBatchMessage>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<WorkerPrimaryMessage<PublicKey>>,
        // Whether we are processing our own batches or the batches of other nodes.
        own_digest: bool,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(batch) = rx_batch.recv() => {
                        // TODO - note how redundant it is to deserialize and calc the batch separately, this needs to be unified

                        // let types::WorkerMessage::<PublicKey>::Batch(deserialized_batch) = bincode::deserialize(&batch.to_vec()).unwrap();

                        // Check that we are able to correctly deserialize the batch
                        // this is deserialization method one and matches patterns observed throughout Narwhal
                        // Note, for now we do not verify transactions, but this can be tested by uncommenting the line below
                        match bincode::deserialize(&batch).unwrap() {
                            WorkerMessage::<PublicKey>::Batch(Batch(transactions)) => {
                                for transaction_padded in transactions {
                                    let serialized_transaction: Vec<u8> = transaction_padded.to_vec()
                                                                            .drain(..SERIALIZED_TRANSACTION_LENGTH)
                                                                            .collect();
                                    // TOOD - do not unwrap here...
                                    let _transaction = GDEXSignedTransaction::deserialize(serialized_transaction).unwrap();
                                    // TODO - verify signatures, ex below could work if we expose API
                                    // TxReceiverHandler::verify_incoming_transaction(serialized_transaction).unwrap();
                                }
                            },
                            // TODO - error handle instead of panic
                            _ => panic!("A transaction failed the pipeline"),
                        };

                        // Check that we are able to correctly deserialize the batch
                        // this is deserialization method two, leveraging a newly defined deserialize batch
                        // let deserialized_batch = deserialize_batch(&batch);
                        // match deserialized_batch {
                        //     Ok(_) => {}
                        //     Err(error) => {
                        //         error!("Received invalid batch, serialization failure: {error}");
                        //     }
                        // }

                        // Hash the batch.
                        let res_digest = serialized_batch_digest(&batch);

                        match res_digest {
                            Ok(digest) => {
                                // Store the batch.
                                store.write(digest, batch).await;

                                // Deliver the batch's digest.
                                let message = match own_digest {
                                    true => WorkerPrimaryMessage::OurBatch(digest, id),
                                    false => WorkerPrimaryMessage::OthersBatch(digest, id),
                                };
                                if tx_digest
                                    .send(message)
                                    .await
                                    .is_err() {
                                    tracing::debug!("{}", DagError::ShuttingDown);
                                };
                            }
                            Err(error) => {
                                error!("Received invalid batch, serialization failure: {error}");
                            }
                        }
                    },

                    // Trigger reconfigure.
                    result = rx_reconfigure.changed() => {
                        result.expect("Committee channel dropped");
                        let message = rx_reconfigure.borrow().clone();
                        if let ReconfigureNotification::Shutdown = message {
                            return;
                        }
                    }
                }
            }
        })
    }
}
