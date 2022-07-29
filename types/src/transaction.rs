//!
//! The transaction class is responsible for parsing client interactions
//! each valid transaction corresponds to a unique state transition within
//! the space of allowable blockchain transitions
//!
use crate::account::{AccountKeyPair, AccountPubKey, AccountSignature};
use blake2::{digest::Update, VarBlake2b};
use crypto::{Digest, Hash, Verifier, DIGEST_LEN};
use gdex_crypto::{hash::CryptoHash, HashValue};
use gdex_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Debug};
type AssetId = u64;

#[derive(Debug, BCSCryptoHash, CryptoHasher, Serialize, Deserialize)]
pub struct CryptoMessage(pub String);

/// A valid payment transaction causes a state transition inside of
/// the BankController object, e.g. it creates a fund transfer from
/// User A to User B provided User A has sufficient funds
#[derive(BCSCryptoHash, Clone, CryptoHasher, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionDigest([u8; DIGEST_LEN]);

impl fmt::Display for TransactionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl TransactionDigest {
    pub fn new(val: [u8; DIGEST_LEN]) -> TransactionDigest {
        TransactionDigest(val)
    }
}

impl From<TransactionDigest> for Digest {
    fn from(digest: TransactionDigest) -> Self {
        Digest::new(digest.0)
    }
}

impl Hash for PaymentRequest {
    type TypedDigest = TransactionDigest;

    fn digest(&self) -> TransactionDigest {
        let hasher_update = |hasher: &mut VarBlake2b| {
            // hasher.update(self.get_from().to_bytes());
            // hasher.update(self.get_to().to_bytes());
            hasher.update(self.get_asset_id().to_le_bytes());
            hasher.update(self.get_amount().to_le_bytes());
        };

        TransactionDigest(crypto::blake2b_256(hasher_update))
    }
}

#[derive(BCSCryptoHash, Clone, CryptoHasher, Debug, Deserialize, Serialize)]
pub enum TransactionVariant {
    PaymentTransaction(PaymentRequest),
}

impl From<PaymentRequest> for TransactionVariant {
    fn from(payment_request: PaymentRequest) -> Self {
        Self::PaymentTransaction(payment_request)
    }
}

/// The TransactionRequest object is responsible for encoding
/// a transaction payload and associated metadata
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionRequest {
    transaction_payload: TransactionVariant,
    sender: AccountPubKey,
    transaction_signature: AccountSignature,
}
impl TransactionRequest {
    pub fn new(
        transaction_payload: TransactionVariant,
        sender: AccountPubKey,
        transaction_signature: AccountSignature,
    ) -> Self {
        TransactionRequest {
            transaction_payload,
            sender,
            transaction_signature,
        }
    }

    pub fn deserialize(byte_vec: Vec<u8>) -> Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(&byte_vec[..])
    }

    pub fn get_transaction_payload(&self) -> &TransactionVariant {
        &self.transaction_payload
    }

    pub fn get_sender(&self) -> &AccountPubKey {
        &self.sender
    }

    pub fn get_transaction_signature(&self) -> &AccountSignature {
        &self.transaction_signature
    }

    pub fn verify_transaction(&self) -> Result<(), crypto::traits::Error> {
        let transaction_hash = self.transaction_payload.hash();
        // self.transaction_signature
        //     .verify(&CryptoMessage(transaction_hash.to_string()), &self.sender)

        self.sender.verify(
            transaction_hash.to_string().as_bytes(),
            &self.transaction_signature,
        )
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(&self)
    }
}

// #[cfg(test)]
pub mod transaction_tests {
    use super::*;

    use crypto::traits::KeyPair;
    use crypto::traits::Signer;
    use rand::{rngs::StdRng, SeedableRng};

    const PRIMARY_ASSET_ID: u64 = 0;

    pub fn keys(seed: [u8; 32]) -> Vec<AccountKeyPair> {
        let mut rng = StdRng::from_seed(seed);
        (0..4).map(|_| AccountKeyPair::generate(&mut rng)).collect()
    }

    pub fn generate_signed_payment_transaction() -> TransactionRequest {
        let kp_sender = keys([0; 32]).pop().unwrap();
        let kp_receiver = keys([1; 32]).pop().unwrap();

        let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
        let transaction = PaymentRequest::new(
            kp_sender.public().clone(),
            kp_receiver.public().clone(),
            PRIMARY_ASSET_ID,
            10,
            dummy_recent_blockhash,
        );

        let transaction_hash = transaction.hash();
        let signed_hash = kp_sender.sign(transaction_hash.to_string().as_bytes());

        TransactionRequest::new(
            TransactionVariant::PaymentTransaction(transaction),
            kp_sender.public().clone(),
            signed_hash,
        )
    }

    #[test]
    // test that a signed payment transaction behaves as expected
    fn create_signed_payment_transaction() {
        let kp_sender = keys([0; 32]).pop().unwrap();
        let kp_receiver = keys([1; 32]).pop().unwrap();

        let dummy_recent_blockhash = CryptoMessage("DUMMY".to_string()).hash();
        let transaction = TransactionVariant::PaymentTransaction(PaymentRequest::new(
            kp_sender.public().clone(),
            kp_receiver.public().clone(),
            PRIMARY_ASSET_ID,
            10,
            dummy_recent_blockhash,
        ));

        let transaction_hash = transaction.hash();
        let signed_hash = kp_sender.sign(transaction_hash.to_string().as_bytes());

        let signed_transaction = TransactionRequest::new(
            transaction.clone(),
            kp_sender.public().clone(),
            signed_hash.clone(),
        );

        // perform transaction checks

        // check valid signature
        signed_transaction.verify_transaction().unwrap();

        let sender_pub_key = kp_sender.public().clone();
        let receiver_pub_key = kp_receiver.public().clone();
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

        assert!(matches!(
            signed_transaction.get_transaction_payload(),
            TransactionVariant::PaymentTransaction(_)
        ));
        let signed_transaction_payload_matched = match signed_transaction.get_transaction_payload()
        {
            TransactionVariant::PaymentTransaction(r) => r,
        };

        assert!(
            signed_transaction_payload_matched.get_amount() == 10,
            "transaction amount does not match transaction input"
        );
        assert!(
            signed_transaction_payload_matched.get_asset_id() == PRIMARY_ASSET_ID,
            "transaction asset id does not match transaction input"
        );
        assert!(
            *signed_transaction_payload_matched.get_from() == sender_pub_key,
            "transaction from does not match transction input"
        );
        assert!(
            *signed_transaction_payload_matched.get_to() == receiver_pub_key,
            "transaction to does not match transction input"
        );
    }

    #[test]
    fn test_serialize_deserialize() {
        let signed_transaction = generate_signed_payment_transaction();

        // perform transaction checks

        let serialized = signed_transaction.serialize().unwrap();
        // check valid signature
        let signed_transaction_deserialized: TransactionRequest =
            TransactionRequest::deserialize(serialized).unwrap();

        assert!(
            *signed_transaction.get_sender() == *signed_transaction_deserialized.get_sender(),
            "transaction sender does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction_signature().clone()
                == signed_transaction_deserialized
                    .get_transaction_signature()
                    .clone(),
            "transaction sender does not match transaction input"
        );

        assert!(matches!(
            signed_transaction_deserialized.get_transaction_payload(),
            TransactionVariant::PaymentTransaction(_)
        ));
        let matched_transaction_payload_deserialized =
            match signed_transaction_deserialized.get_transaction_payload() {
                TransactionVariant::PaymentTransaction(r) => r,
            };

        let matched_transaction_payload = match signed_transaction.get_transaction_payload() {
            TransactionVariant::PaymentTransaction(r) => r,
        };

        // verify transactions
        let transaction_hash_0 = matched_transaction_payload.digest();
        let transaction_hash_1 = matched_transaction_payload_deserialized.digest();
        assert!(
            transaction_hash_0 == transaction_hash_1,
            "hashes appears to have violated determinism"
        );

        assert!(
            matched_transaction_payload.get_amount()
                == matched_transaction_payload_deserialized.get_amount(),
            "transaction amount does not match transaction input"
        );
        assert!(
            matched_transaction_payload.get_asset_id()
                == matched_transaction_payload_deserialized.get_asset_id(),
            "transaction asset id does not match transaction input"
        );
        assert!(
            *matched_transaction_payload.get_from()
                == *matched_transaction_payload_deserialized.get_from(),
            "transaction from does not match transction input"
        );
        assert!(
            *matched_transaction_payload.get_to()
                == *matched_transaction_payload_deserialized.get_to(),
            "transaction to does not match transction input"
        );
    }
}
