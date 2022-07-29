//!
//! account objects are attached to specific Controllers and are
//! responsible for keeping important controller-specific data
//!
use std::{collections::HashMap, fmt::Debug};
use types::{AccountBalance, AccountPubKey, AssetId};

/// BankAccount is consumed by the BankController
/// the account contains a map of asset ids onto
/// associated balances for the corersponding account
#[derive(Debug)]
pub struct BankAccount {
    account_pub_key: AccountPubKey,
    balances: HashMap<AssetId, AccountBalance>,
}
impl BankAccount {
    pub fn new(account_pub_key: AccountPubKey) -> Self {
        BankAccount {
            account_pub_key,
            balances: HashMap::new(),
        }
    }

    pub fn get_account_pub_key(&self) -> &AccountPubKey {
        &self.account_pub_key
    }

    pub fn get_balances(&self) -> &HashMap<AssetId, AccountBalance> {
        &self.balances
    }

    pub fn set_balance(&mut self, asset_id: AssetId, amount: u64) {
        self.balances.insert(asset_id, amount);
    }
}