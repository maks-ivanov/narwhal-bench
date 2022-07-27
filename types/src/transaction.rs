//!
//! The transaction class is responsible for parsing client interactions
//! each valid transaction corresponds to a unique state transition within
//! the space of allowable blockchain transitions
//!
use crate::account::{AccountPubKey, AccountSignature};
use gdex_crypto::{hash::CryptoHash, HashValue, Signature};
use gdex_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
type AssetId = u64;

#[derive(Debug, BCSCryptoHash, CryptoHasher, Serialize, Deserialize)]
pub struct CryptoMessage(pub String);

/// A valid payment transaction causes a state transition inside of
/// the BankController object, e.g. it creates a fund transfer from
/// User A to User B provided User A has sufficient funds
#[derive(BCSCryptoHash, Copy, Clone, CryptoHasher, Debug, Deserialize, Serialize)]
pub struct PaymentRequest {
    // storing from here is not redundant as from may not equal sender
    // e.g. we are preserving the possibility of adding re-key functionality
    from: AccountPubKey,
    to: AccountPubKey,
    asset_id: AssetId,
    amount: u64,
    // it is necessary to pass a recent block hash to make sure that a transaction cannot
    // be duplicated, moreover it is used to gaurantee that a submitted transaction was
    // created within a well designated lookback
    recent_block_hash: HashValue,
}
impl PaymentRequest {
    pub fn new(
        from: AccountPubKey,
        to: AccountPubKey,
        asset_id: AssetId,
        amount: u64,
        recent_block_hash: HashValue,
    ) -> Self {
        PaymentRequest {
            from,
            to,
            asset_id,
            amount,
            recent_block_hash,
        }
    }

    pub fn get_from(&self) -> &AccountPubKey {
        &self.from
    }

    pub fn get_to(&self) -> &AccountPubKey {
        &self.to
    }

    pub fn get_asset_id(&self) -> AssetId {
        self.asset_id
    }

    pub fn get_amount(&self) -> u64 {
        self.amount
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransactionVariant {
    PaymentTransaction(PaymentRequest),
}

/// The TransactionRequest object is responsible for encoding
/// a transaction payload and associated metadata
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionRequest<TransactionVariant>
where
    TransactionVariant: Clone + CryptoHash + Debug + Serialize,
{
    transaction: TransactionVariant,
    sender: AccountPubKey,
    transaction_signature: AccountSignature,
}
impl<TransactionVariant> TransactionRequest<TransactionVariant>
where
    TransactionVariant: Clone + Copy + CryptoHash + Debug + Serialize + for<'a> Deserialize<'a>,
{
    pub fn new(
        transaction: TransactionVariant,
        sender: AccountPubKey,
        transaction_signature: AccountSignature,
    ) -> Self {
        TransactionRequest {
            transaction,
            sender,
            transaction_signature,
        }
    }

    pub fn deserialize(byte_vec: Vec<u8>) -> Result<Self, serde_json::Error> {
        let new_transaction = serde_json::from_slice(&byte_vec[..]);
        new_transaction
    }

    pub fn get_transaction(&self) -> &TransactionVariant {
        &self.transaction
    }

    pub fn get_sender(&self) -> &AccountPubKey {
        &self.sender
    }

    pub fn get_transaction_signature(&self) -> &AccountSignature {
        &self.transaction_signature
    }

    pub fn verify_transaction(&self) -> Result<(), gdex_crypto::error::Error> {
        let transaction_hash = self.transaction.hash();
        self.transaction_signature
            .verify(&CryptoMessage(transaction_hash.to_string()), &self.sender)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use crate::account::AccountPrivKey;
    use gdex_crypto::{SigningKey, Uniform};

    const PRIMARY_ASSET_ID: u64 = 0;

    #[test]
    // test that a signed payment transaction behaves as expected
    fn create_signed_payment_transaction() {
        let private_key = AccountPrivKey::generate_for_testing(0);
        let sender_pub_key = (&private_key).into();

        let receiver_private_key = AccountPrivKey::generate_for_testing(1);
        let receiver_pub_key = (&receiver_private_key).into();
        let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
        let transaction = PaymentRequest::new(
            sender_pub_key,
            receiver_pub_key,
            PRIMARY_ASSET_ID,
            10,
            dummy_recent_blockhash,
        );

        let transaction_hash = transaction.hash();
        let signed_hash = private_key.sign(&CryptoMessage(transaction_hash.to_string()));
        let signed_transaction = TransactionRequest::<PaymentRequest>::new(
            transaction,
            sender_pub_key,
            signed_hash.clone(),
        );

        // perform transaction checks

        // check valid signature
        signed_transaction.verify_transaction().unwrap();

        // check valid signature

        // verify deterministic hashing
        let transaction_hash_0 = transaction.hash();
        let transaction_hash_1 = transaction.hash();
        assert!(
            transaction_hash_0 == transaction_hash_1,
            "hashes appears to have violated determinism"
        );

        assert!(
            *signed_transaction.get_sender() == sender_pub_key,
            "transaction sender does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction_signature().clone() == signed_hash,
            "transaction sender does not match transaction input"
        );

        assert!(
            signed_transaction.get_transaction().get_amount() == 10,
            "transaction amount does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction().get_asset_id() == PRIMARY_ASSET_ID,
            "transaction asset id does not match transaction input"
        );
        assert!(
            *signed_transaction.get_transaction().get_from() == sender_pub_key,
            "transaction from does not match transction input"
        );
        assert!(
            *signed_transaction.get_transaction().get_to() == receiver_pub_key,
            "transaction to does not match transction input"
        );
    }

    #[test]
    fn test_serialize_deserialize() {
        let private_key = AccountPrivKey::generate_for_testing(0);
        let sender_pub_key = (&private_key).into();

        let receiver_private_key = AccountPrivKey::generate_for_testing(1);
        let receiver_pub_key = (&receiver_private_key).into();
        let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
        let transaction = PaymentRequest::new(
            sender_pub_key,
            receiver_pub_key,
            PRIMARY_ASSET_ID,
            10,
            dummy_recent_blockhash,
        );

        let transaction_hash = transaction.hash();
        let signed_hash = private_key.sign(&CryptoMessage(transaction_hash.to_string()));
        let signed_transaction = TransactionRequest::<PaymentRequest>::new(
            transaction,
            sender_pub_key,
            signed_hash.clone(),
        );

        // perform transaction checks

        let serialized = signed_transaction.serialize().unwrap();
        // check valid signature
        let _signed_transaction: TransactionRequest<PaymentRequest> =
            TransactionRequest::<PaymentRequest>::deserialize(serialized).unwrap();

        // verify transactions
        let transaction_hash_0 = signed_transaction.get_transaction().hash();
        let transaction_hash_1 = _signed_transaction.get_transaction().hash();
        assert!(
            transaction_hash_0 == transaction_hash_1,
            "hashes appears to have violated determinism"
        );

        assert!(
            *signed_transaction.get_sender() == *_signed_transaction.get_sender(),
            "transaction sender does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction_signature().clone()
                == _signed_transaction.get_transaction_signature().clone(),
            "transaction sender does not match transaction input"
        );

        assert!(
            signed_transaction.get_transaction().get_amount()
                == _signed_transaction.get_transaction().get_amount(),
            "transaction amount does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction().get_asset_id()
                == _signed_transaction.get_transaction().get_asset_id(),
            "transaction asset id does not match transaction input"
        );
        assert!(
            *signed_transaction.get_transaction().get_from()
                == *_signed_transaction.get_transaction().get_from(),
            "transaction from does not match transction input"
        );
        assert!(
            *signed_transaction.get_transaction().get_to()
                == *_signed_transaction.get_transaction().get_to(),
            "transaction to does not match transction input"
        );
    }
}
