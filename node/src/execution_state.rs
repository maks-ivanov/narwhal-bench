// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use async_trait::async_trait;
use config::Committee;
use consensus::ConsensusOutput;
use crypto::traits::{KeyPair, VerifyingKey};
use executor::{ExecutionIndices, ExecutionState, ExecutionStateError};
use futures::executor::block_on;
use proc::bank::BankController;
use rand::{rngs::StdRng, SeedableRng};
use std::{fmt, fmt::Display, path::Path, sync::Mutex};
use store::{
    reopen,
    rocks::{open_cf, DBMap},
    Store,
};
use thiserror::Error;
use types::{AccountKeyPair, BankError, GDEXSignedTransaction, TransactionVariant};

/// A simple/dumb execution engine.
pub struct SimpleExecutionState;

#[async_trait]
impl ExecutionState for SimpleExecutionState {
    type Transaction = String;
    type Error = SimpleExecutionError;
    type Outcome = Vec<u8>;

    async fn handle_consensus_transaction<PublicKey: VerifyingKey>(
        &self,
        _consensus_output: &ConsensusOutput<PublicKey>,
        _execution_indices: ExecutionIndices,
        _transaction: Self::Transaction,
    ) -> Result<(Self::Outcome, Option<Committee<PublicKey>>), Self::Error> {
        Ok((Vec::default(), None))
    }

    fn ask_consensus_write_lock(&self) -> bool {
        true
    }

    fn release_consensus_write_lock(&self) {}

    async fn load_execution_indices(&self) -> Result<ExecutionIndices, Self::Error> {
        Ok(ExecutionIndices::default())
    }
}

/// A simple/dumb execution error.
#[derive(Debug, Error)]
pub enum SimpleExecutionError {
    #[error("Something went wrong in the authority")]
    ServerError,

    #[error("The client made something bad")]
    ClientError,
}

#[async_trait]
impl ExecutionStateError for SimpleExecutionError {
    fn node_error(&self) -> bool {
        match self {
            Self::ServerError => true,
            Self::ClientError => false,
        }
    }

    fn to_string(&self) -> String {
        ToString::to_string(&self)
    }
}

/// A more advanced execution state for testing.
pub struct AdvancedExecutionState {
    store: Store<u64, ExecutionIndices>,
    bank_controller: Mutex<BankController>,
    pub primary_manager: AccountKeyPair,
}

impl std::fmt::Debug for AdvancedExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", block_on(self.get_execution_indices()))
    }
}

impl Default for AdvancedExecutionState {
    fn default() -> Self {
        Self::new(tempfile::tempdir().unwrap().path())
    }
}

#[async_trait]
impl ExecutionState for AdvancedExecutionState {
    type Transaction = GDEXSignedTransaction;
    type Error = AdvancedExecutionStateError;
    type Outcome = Vec<u8>;

    async fn handle_consensus_transaction<PublicKey: VerifyingKey>(
        &self,
        _consensus_output: &ConsensusOutput<PublicKey>,
        execution_indices: ExecutionIndices,
        signed_transaction: Self::Transaction,
    ) -> Result<(Self::Outcome, Option<Committee<PublicKey>>), Self::Error> {
        let transaction = signed_transaction.get_transaction_payload();
        let execution = match transaction.get_variant() {
            TransactionVariant::PaymentTransaction(_payment) => {
                self.store
                    .write(Self::INDICES_ADDRESS, execution_indices)
                    .await;
                // FOR NOW WE DO NOT PROCESS THE TRANSACTINO AS THIS APPEARS TO BREAK THE NETWORK
                // self.bank_controller.lock().unwrap().transfer(
                //     transaction.get_sender(),
                //     payment.get_receiver(),
                //     payment.get_asset_id(),
                //     payment.get_amount(),
                // )
                Ok(())
            }
            TransactionVariant::CreateAssetTransaction(_create_asset) => self
                .bank_controller
                .lock()
                .unwrap()
                .create_asset(transaction.get_sender()),
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

impl AdvancedExecutionState {
    /// The address at which to store the indices (rocksdb is a key-value store).
    pub const INDICES_ADDRESS: u64 = 14;

    /// Create a new test state.
    pub fn new(store_path: &Path) -> Self {
        const STATE_CF: &str = "test_state";
        let rocksdb = open_cf(store_path, None, &[STATE_CF]).unwrap();
        let map = reopen!(&rocksdb, STATE_CF;<u64, ExecutionIndices>);
        let bank_controller: Mutex<BankController> = Mutex::new(BankController::default());
        // let primary_manager = keys([0; 32]).pop().unwrap();
        let seed = [0; 32];
        let mut rng = StdRng::from_seed(seed);
        let primary_manager = AccountKeyPair::generate(&mut rng);

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

#[async_trait]
impl ExecutionStateError for AdvancedExecutionStateError {
    fn node_error(&self) -> bool {
        match self {
            Self::VMError(_) => true,
        }
    }

    fn to_string(&self) -> String {
        ToString::to_string(&self)
    }
}

#[derive(Debug, Error)]
pub enum AdvancedExecutionStateError {
    VMError(#[from] BankError),
}
impl Display for AdvancedExecutionStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", executor::ExecutionStateError::to_string(self))
    }
}
