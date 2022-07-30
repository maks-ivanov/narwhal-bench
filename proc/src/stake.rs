//!
//! this controller is responsible for managing user staking
//! it relies on BankController and only accesses the 0th (first) created asset
//!
//!
//! TODO
//! 0.) ADD SIZE CHECKS ON TRANSACTIONS
//!
extern crate types;

use super::account::StakeAccount;
use super::bank::{BankController, PRIMARY_ASSET_ID};
use std::collections::HashMap;
use types::{AccountPubKey, GDEXError};

// The stake controller is responsible for accessing & modifying user balances
pub struct StakeController {
    stake_accounts: HashMap<AccountPubKey, StakeAccount>,
    total_staked: u64,
}
impl StakeController {
    pub fn new() -> Self {
        StakeController {
            stake_accounts: HashMap::new(),
            total_staked: 0,
        }
    }

    pub fn create_account(&mut self, account_pub_key: &AccountPubKey) -> Result<(), GDEXError> {
        if self.stake_accounts.contains_key(account_pub_key) {
            Err(GDEXError::AccountCreation("Account already exists!".to_string()))
        } else {
            self.stake_accounts
                .insert(account_pub_key.clone(), StakeAccount::new(account_pub_key.clone()));
            Ok(())
        }
    }

    pub fn get_staked(&self, account_pub_key: &AccountPubKey) -> Result<u64, GDEXError> {
        let stake_account = self
            .stake_accounts
            .get(account_pub_key)
            .ok_or_else(|| GDEXError::AccountLookup("Failed to find account".to_string()))?;
        Ok(stake_account.get_staked_amount())
    }

    // stake funds to participate in consensus
    pub fn stake(
        &mut self,
        bank_controller: &mut BankController,
        account_pub_key: &AccountPubKey,
        amount: u64,
    ) -> Result<(), GDEXError> {
        bank_controller.update_balance(account_pub_key, PRIMARY_ASSET_ID, -(amount as i64))?;
        self.total_staked += amount;
        let lookup = self.stake_accounts.get_mut(account_pub_key);
        match lookup {
            Some(stake_account) => {
                stake_account.set_staked_amount(stake_account.get_staked_amount() + amount as u64);
                Ok(())
            }
            None => {
                let mut new_stake_account = StakeAccount::new(account_pub_key.clone());
                new_stake_account.set_staked_amount(amount);
                self.stake_accounts.insert(account_pub_key.clone(), new_stake_account);
                Ok(())
            }
        }
    }

    // TODO #0 //
    pub fn unstake(
        &mut self,
        bank_controller: &mut BankController,
        account_pub_key: &AccountPubKey,
        amount: u64,
    ) -> Result<(), GDEXError> {
        self.total_staked -= amount;
        bank_controller.update_balance(account_pub_key, PRIMARY_ASSET_ID, amount as i64)?;
        let stake_account = self
            .stake_accounts
            .get_mut(account_pub_key)
            .ok_or_else(|| GDEXError::AccountLookup("Failed to find account".to_string()))?;
        stake_account.set_staked_amount(stake_account.get_staked_amount() - amount);
        Ok(())
    }

    pub fn get_accounts(&self) -> &HashMap<AccountPubKey, StakeAccount> {
        &self.stake_accounts
    }

    pub fn get_total_staked(&self) -> u64 {
        self.total_staked
    }
}

impl Default for StakeController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::bank::{CREATED_ASSET_BALANCE, PRIMARY_ASSET_ID};
    use super::types::{AccountKeyPair};
    use crypto::traits::KeyPair;
    use super::*;

    use rand::{rngs::StdRng, SeedableRng};

    pub fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
        let mut rng = StdRng::from_seed(seed);
        (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
    }


    const STAKE_AMOUNT: u64 = 1_000;
    #[test]
    fn stake() {
        let kp_staker = keys([0; 32]).pop().unwrap();

        let mut bank_controller = BankController::new();
        bank_controller.create_asset(&kp_staker.public()).unwrap();
        bank_controller.create_asset(&kp_staker.public()).unwrap();

        let mut stake_controller = StakeController::new();
        stake_controller.create_account(&kp_staker.public()).unwrap();

        stake_controller
            .stake(&mut bank_controller, &kp_staker.public(), STAKE_AMOUNT)
            .unwrap();
        assert!(
            bank_controller.get_balance(&kp_staker.public(), PRIMARY_ASSET_ID).unwrap()
                == CREATED_ASSET_BALANCE - STAKE_AMOUNT,
            "unexpected balance"
        );
        assert!(
            stake_controller.get_accounts().keys().len() == 1,
            "unexpected number of accounts"
        );
        assert!(
            stake_controller.get_staked(&kp_staker.public()).unwrap() == STAKE_AMOUNT,
            "unexpected stake amount"
        );
        assert!(
            stake_controller.get_total_staked() == STAKE_AMOUNT,
            "unexpected total staked amount"
        );
    }

    // TODO #0 //
    #[test]
    #[should_panic]
    fn failed_stake() {
        let kp_staker = keys([0; 32]).pop().unwrap();

        let mut bank_controller = BankController::new();
        bank_controller.create_asset(&kp_staker.public()).unwrap();
        bank_controller.create_asset(&kp_staker.public()).unwrap();

        let mut stake_controller = StakeController::new();
        assert!(
            bank_controller.get_balance(&kp_staker.public(), PRIMARY_ASSET_ID).unwrap() == 0,
            "unexpected balance"
        );
        // staking without funding should create error
        let kp_staker_2 = keys([1; 32]).pop().unwrap();
        stake_controller
            .stake(&mut bank_controller, &kp_staker_2.public(), STAKE_AMOUNT)
            .unwrap();
    }
}
