//!
//! toy consensus model that imitates a simple PoS
//! features still need further fleshing out
//!

use super::router::{asset_creation_transaction, route_transaction, stake_transaction};
use super::{bank::BankController, spot::SpotController, stake::StakeController};
use types::{AccountPrivKey, AccountPubKey, GDEXError, TransactionRequest, TransactionVariant};

// the consensus manager owns all Controllers and is responsible for
// processing transactions, updating state, and reaching consensus in "toy" conditions
pub struct MasterController {
    bank_controller: BankController,
    spot_controller: SpotController,
    stake_controller: StakeController,
}
impl MasterController {
    pub fn new() -> Self {
        let (pub_key, private_key) = generate_key_pair();
        MasterController {
            bank_controller: BankController::new(),
            spot_controller: SpotController::new(),
            stake_controller: StakeController::new(),
        }
    }

    pub fn get_bank_controller(&mut self) -> &mut BankController {
        &mut self.bank_controller
    }

    pub fn get_stake_controller(&mut self) -> &mut StakeController {
        &mut self.stake_controller
    }

    pub fn get_spot_controller(&mut self) -> &mut SpotController {
        &mut self.spot_controller
    }
}

impl Default for ControllerManager {
    fn default() -> Self {
        Self::new()
    }
}
