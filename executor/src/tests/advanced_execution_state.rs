use super::*;
use crate::{
    fixtures::{
        create_signed_payment_transaction, keys, test_batch, test_certificate, test_store,
        test_transaction_certificates,
    },
    ExecutionIndices, ExecutionState, ExecutionStateError,
};
use async_trait::async_trait;
use config::Committee;
use consensus::ConsensusOutput;
use crypto::{
    ed25519::Ed25519PublicKey,
    traits::{KeyPair, VerifyingKey},
};

use futures::executor::block_on;
use proc::bank::BankController;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use store::{
    reopen,
    rocks::{open_cf, DBMap},
    Store,
};
use test_utils::committee;
use thiserror::Error;
use tokio::sync::mpsc::channel;
use types::{
    AccountKeyPair, Batch, GDEXError, SequenceNumber, TransactionRequest, TransactionVariant,
};
use worker::WorkerMessage;

/// A more advanced execution state for testing.
pub struct AdvancedTestState {
    store: Store<u64, ExecutionIndices>,
    bank_controller: Arc<Mutex<BankController>>,
    pub primary_manager: AccountKeyPair,
}

impl std::fmt::Debug for AdvancedTestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", block_on(self.get_execution_indices()))
    }
}

impl Default for AdvancedTestState {
    fn default() -> Self {
        Self::new(tempfile::tempdir().unwrap().path())
    }
}

#[derive(Debug, Error)]
pub enum AdvancedTestStateError {
    #[error("Something went wrong in the virtual machine")]
    VMError(GDEXError),
}

#[async_trait]
impl ExecutionStateError for AdvancedTestStateError {
    fn node_error(&self) -> bool {
        match self {
            Self::VMError(_) => true,
        }
    }

    fn to_string(&self) -> String {
        ToString::to_string(&self)
    }
}

#[async_trait]
impl ExecutionState for AdvancedTestState {
    type Transaction = TransactionRequest;
    type Error = AdvancedTestStateError;
    type Outcome = Vec<u8>;

    async fn handle_consensus_transaction<PublicKey: VerifyingKey>(
        &self,
        _consensus_output: &ConsensusOutput<PublicKey>,
        execution_indices: ExecutionIndices,
        request: Self::Transaction,
    ) -> Result<(Self::Outcome, Option<Committee<PublicKey>>), Self::Error> {
        let execution = match request.get_transaction_payload() {
            TransactionVariant::PaymentTransaction(payment) => {
                self.store
                    .write(Self::INDICES_ADDRESS, execution_indices)
                    .await;
                self.bank_controller.lock().unwrap().transfer(
                    payment.get_from(),
                    payment.get_to(),
                    payment.get_asset_id(),
                    payment.get_amount(),
                )
            }
            _ => {
                return Err(Self::Error::VMError(GDEXError::OrderProc("Only payment transactions are currently supported".to_string())))
            },
        };
        match execution {
            Ok(_) => Ok((Vec::default(), None)),
            Err(err) => Err(Self::Error::VMError(err)),
        }
    }

    fn ask_consensus_write_lock(&self) -> bool {
        true
    }

    fn release_consensus_write_lock(&self) {}

    async fn load_execution_indices(&self) -> Result<ExecutionIndices, Self::Error> {
        let indices = self
            .store
            .read(Self::INDICES_ADDRESS)
            .await
            .unwrap()
            .unwrap_or_default();
        Ok(indices)
    }
}

impl AdvancedTestState {
    /// The address at which to store the indices (rocksdb is a key-value store).
    pub const INDICES_ADDRESS: u64 = 14;

    /// Create a new test state.
    pub fn new(store_path: &Path) -> Self {
        const STATE_CF: &str = "test_state";
        let rocksdb = open_cf(store_path, None, &[STATE_CF]).unwrap();
        let map = reopen!(&rocksdb, STATE_CF;<u64, ExecutionIndices>);
        let bank_controller: Arc<Mutex<BankController>> =
            Arc::new(Mutex::new(BankController::default()));
        let primary_manager = keys([0; 32]).pop().unwrap();
        bank_controller
            .lock()
            .unwrap()
            .create_asset(&primary_manager.public().clone())
            .unwrap();
        Self {
            store: Store::new(map),
            bank_controller,
            primary_manager,
        }
    }

    /// Load the execution indices; ie. the state.
    pub async fn get_execution_indices(&self) -> ExecutionIndices {
        self.load_execution_indices().await.unwrap()
    }
}

#[tokio::test]
async fn execute_advanced_transactions() {
    let (tx_executor, rx_executor) = channel(10);
    let (tx_output, mut rx_output) = channel(10);

    let committee = committee(None);
    let message = ReconfigureNotification::NewCommittee(committee);
    let (_tx_reconfigure, rx_reconfigure) = watch::channel(message);

    // Spawn the executor.
    let store = test_store();

    let execution_state = Arc::new(AdvancedTestState::default());
    Core::<AdvancedTestState, Ed25519PublicKey>::spawn(
        store.clone(),
        execution_state.clone(),
        rx_reconfigure,
        /* rx_subscriber */ rx_executor,
        tx_output,
    );

    // Feed a malformed transaction to the mock sequencer
    let tx0 = create_signed_payment_transaction(
        execution_state.primary_manager.copy(),
        /* asset_id */ 0,
        /* amount */ 10,
    );
    // let tx1 = create_signed_payment_transaction(execution_state.clone().primary_manager,/* asset_id */ 0, /* amount */ 100);
    let (digest, batch) = test_batch(vec![tx0]);

    // verify we can deserialize objects in the batch

    // git the consensus workers' batch message to retrieve a list of transactions.
    let transactions = match bincode::deserialize(&batch).unwrap() {
        WorkerMessage::<Ed25519PublicKey>::Batch(Batch(x)) => x,
        _ => panic!("Error has occurred"),
    };

    let serialized = &transactions.clone()[0];

    // verify we can deserialize objects in the batch
    let _transaction: TransactionRequest = bincode::deserialize(&serialized).unwrap();

    store.write(digest, batch).await;

    let payload = [(digest, 0)].iter().cloned().collect();
    let certificate = test_certificate(payload);

    let message = ConsensusOutput {
        certificate,
        consensus_index: SequenceNumber::default(),
    };
    tx_executor.send(message).await.unwrap();

    // Feed two certificates with good transactions to the executor.
    let certificates = test_transaction_certificates(
        /* keypair */ execution_state.primary_manager.copy(),
        /* certificates */ 2,
        /* batches_per_certificate */ 2,
        /* transactions_per_batch */ 2,
    );
    for (certificate, batches) in certificates {
        for (digest, batch) in batches {
            store.write(digest, batch).await;
        }
        let message = ConsensusOutput {
            certificate,
            consensus_index: SequenceNumber::default(),
        };
        tx_executor.send(message).await.unwrap();
    }

    // Ensure the execution state is updated accordingly.
    rx_output.recv().await;
    let expected = ExecutionIndices {
        next_certificate_index: 3,
        next_batch_index: 0,
        next_transaction_index: 0,
    };
    assert_eq!(execution_state.get_execution_indices().await, expected);
}
