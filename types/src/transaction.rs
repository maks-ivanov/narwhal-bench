//!
//! The transaction class is responsible for parsing client interactions
//! each valid transaction corresponds to a unique state transition within
//! the space of allowable blockchain transitions
//!
use crate::{AccountKeyPair, AccountPubKey, AccountSignature, BatchDigest, OrderSide};
use blake2::{digest::Update, VarBlake2b};
use crypto::{Digest, Hash, Verifier, DIGEST_LEN};
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Debug, time::SystemTime};

type AssetId = u64;
/// A valid payment transaction causes a state transition inside of
/// the BankController object, e.g. it creates a fund transfer from
/// User A to User B provided User A has sufficient funds
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PaymentRequest {
    // storing from here is not redundant as from may not equal sender
    // e.g. we are preserving the possibility of adding re-key functionality
    sender: AccountPubKey,
    receiver: AccountPubKey,
    asset_id: AssetId,
    amount: u64,
    // it is necessary to pass a recent block hash to make sure that a transaction cannot
    // be duplicated, moreover it is used to gaurantee that a submitted transaction was
    // created within a well designated lookback, TODO - implement such checks in pipeline
    recent_batch_digest: BatchDigest,
}
impl PaymentRequest {
    pub fn new(
        sender: AccountPubKey,
        receiver: AccountPubKey,
        asset_id: AssetId,
        amount: u64,
        recent_batch_digest: BatchDigest,
    ) -> Self {
        PaymentRequest {
            sender,
            receiver,
            asset_id,
            amount,
            recent_batch_digest,
        }
    }

    pub fn get_sender(&self) -> &AccountPubKey {
        &self.sender
    }

    pub fn get_receiver(&self) -> &AccountPubKey {
        &self.receiver
    }

    pub fn get_asset_id(&self) -> AssetId {
        self.asset_id
    }

    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    pub fn get_recent_batch_digest(&self) -> &BatchDigest {
        &self.recent_batch_digest
    }
}

/// A transaction for creating a new asset in the BankController
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateAssetRequest {
    sender: AccountPubKey,
    recent_batch_digest: BatchDigest,
}

impl CreateAssetRequest {
    pub fn new(sender: AccountPubKey, recent_batch_digest: BatchDigest) -> Self {
        CreateAssetRequest {
            sender,
            recent_batch_digest,
        }
    }

    pub fn get_sender(&self) -> &AccountPubKey {
        &self.sender
    }

    pub fn get_recent_batch_digest(&self) -> &BatchDigest {
        &self.recent_batch_digest
    }
}

pub enum OrderRequest {
    Market {
        sender: AccountPubKey,
        base_asset: AssetId,
        quote_asset: AssetId,
        side: OrderSide,
        quantity: u64,
        ts: SystemTime,
    },

    Limit {
        sender: AccountPubKey,
        base_asset: AssetId,
        quote_asset: AssetId,
        side: OrderSide,
        price: u64,
        quantity: u64,
        ts: SystemTime,
    },

    Amend {
        sender: AccountPubKey,
        id: u64,
        side: OrderSide,
        price: u64,
        quantity: u64,
        ts: SystemTime,
    },

    CancelOrder {
        sender: AccountPubKey,
        id: u64,
        side: OrderSide,
        //ts: SystemTime,
    },
}

impl OrderRequest {

    pub fn get_sender(&self) -> &AccountPubKey {
        match self {
            OrderRequest::Market({sender, ...}) => sender,
            // OrderRequest::Limit(r) => r.sender,
            // OrderRequest::Limit(r) => r.sender,
        }
    }

}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransactionVariant {
    PaymentTransaction(PaymentRequest),
    CreateAssetTransaction(CreateAssetRequest),
    OrderTransaction(OrderRequest),
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

impl Hash for TransactionVariant {
    type TypedDigest = TransactionDigest;

    fn digest(&self) -> TransactionDigest {
        match self {
            TransactionVariant::PaymentTransaction(payment) => {
                let hasher_update = |hasher: &mut VarBlake2b| {
                    hasher.update(payment.get_sender().0.to_bytes());
                    hasher.update(payment.get_receiver().0.as_bytes());
                    hasher.update(payment.get_asset_id().to_le_bytes());
                    hasher.update(payment.get_amount().to_le_bytes());
                    // can we avoid turning into a string first?
                    hasher.update(payment.get_recent_batch_digest().to_string().as_bytes());
                };
                TransactionDigest(crypto::blake2b_256(hasher_update))
            }
            TransactionVariant::CreateAssetTransaction(payment) => {
                let hasher_update = |hasher: &mut VarBlake2b| {
                    hasher.update(payment.get_sender().0.to_bytes());
                    // can we avoid turning into a string first?
                    hasher.update(payment.get_recent_batch_digest().to_string().as_bytes());
                };
                TransactionDigest(crypto::blake2b_256(hasher_update))
            }
            TransactionVariant::OrderTransaction(order) => {
                let hasher_update = |hasher: &mut VarBlake2b| {
                    hasher.update(order.get_sender().0.to_bytes());
                    // can we avoid turning into a string first?
                    match order {
                        OrderRequest::Amend(r) => {hasher.update(payment.get_recent_batch_digest().to_string().as_bytes());}
                    }
                    
                };
                TransactionDigest(crypto::blake2b_256(hasher_update))
            }

        }
    }
}

#[derive(Debug)]
pub enum TransactionRequestError {
    InvalidSender(String),
    FailedVerification(crypto::traits::Error),
    Serialization(Box<bincode::ErrorKind>),
    Deserialization(Box<bincode::ErrorKind>),
}

/// The TransactionRequest object is responsible for encoding
/// a transaction payload and associated metadata which allows
/// validation of sender logic
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionRequest {
    transaction_payload: TransactionVariant,
    transaction_signature: AccountSignature,
}
impl TransactionRequest {
    pub fn new(
        transaction_payload: TransactionVariant,
        transaction_signature: AccountSignature,
    ) -> Self {
        TransactionRequest {
            transaction_payload,
            transaction_signature,
        }
    }

    pub fn deserialize(byte_vec: Vec<u8>) -> Result<Self, TransactionRequestError> {
        match bincode::deserialize(&byte_vec[..]) {
            Ok(result) => Ok(result),
            Err(err) => Err(TransactionRequestError::Deserialization(err)),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionRequestError> {
        match bincode::serialize(&self) {
            Ok(result) => Ok(result),
            Err(err) => Err(TransactionRequestError::Serialization(err)),
        }
    }

    pub fn get_transaction_payload(&self) -> &TransactionVariant {
        &self.transaction_payload
    }

    pub fn get_sender(&self) -> &AccountPubKey {
        match &self.transaction_payload {
            TransactionVariant::PaymentTransaction(r) => r.get_sender(),
            TransactionVariant::CreateAssetTransaction(r) => r.get_sender(),
        }
    }

    pub fn get_transaction_signature(&self) -> &AccountSignature {
        &self.transaction_signature
    }

    pub fn verify_transaction(&self) -> Result<(), TransactionRequestError> {
        let transaction_digest = self.transaction_payload.digest();

        match self.get_sender().verify(
            transaction_digest.to_string().as_bytes(),
            &self.transaction_signature,
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(TransactionRequestError::FailedVerification(err)),
        }
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

        let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);
        let transaction = TransactionVariant::PaymentTransaction(PaymentRequest::new(
            kp_sender.public().clone(),
            kp_receiver.public().clone(),
            PRIMARY_ASSET_ID,
            10,
            dummy_batch_digest,
        ));

        let transaction_digest = transaction.digest();
        let signed_digest = kp_sender.sign(transaction_digest.to_string().as_bytes());

        TransactionRequest::new(transaction, signed_digest)
    }

    #[test]
    // test that a signed payment transaction behaves as expected
    fn create_signed_payment_transaction() {
        let kp_sender = keys([0; 32]).pop().unwrap();
        let kp_receiver = keys([1; 32]).pop().unwrap();

        let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);
        let transaction = TransactionVariant::PaymentTransaction(PaymentRequest::new(
            kp_sender.public().clone(),
            kp_receiver.public().clone(),
            PRIMARY_ASSET_ID,
            10,
            dummy_batch_digest,
        ));

        let transaction_digest = transaction.digest();
        let signed_digest = kp_sender.sign(transaction_digest.to_string().as_bytes());

        let signed_transaction =
            TransactionRequest::new(transaction.clone(), signed_digest.clone());

        // perform transaction checks

        // check valid signature
        signed_transaction.verify_transaction().unwrap();

        let sender_pub_key = kp_sender.public().clone();
        let receiver_pub_key = kp_receiver.public().clone();
        // verify deterministic hashing
        let transaction_hash_0 = transaction.digest();
        let transaction_hash_1 = transaction.digest();
        assert!(
            transaction_hash_0 == transaction_hash_1,
            "hashes appears to have violated determinism"
        );

        assert!(
            *signed_transaction.get_sender() == sender_pub_key,
            "transaction sender does not match transaction input"
        );
        assert!(
            signed_transaction.get_transaction_signature().clone() == signed_digest,
            "transaction sender does not match transaction input"
        );

        assert!(matches!(
            signed_transaction.get_transaction_payload(),
            TransactionVariant::PaymentTransaction(_)
        ));
        let signed_transaction_payload_matched = match signed_transaction.get_transaction_payload()
        {
            TransactionVariant::PaymentTransaction(r) => r,
            _ => {
                panic!("An unexpected error occurred while reading the payment transaction");
            }
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
            *signed_transaction_payload_matched.get_sender() == sender_pub_key,
            "transaction from does not match transction input"
        );
        assert!(
            *signed_transaction_payload_matched.get_receiver() == receiver_pub_key,
            "transaction to does not match transction input"
        );
    }

    #[test]
    fn create_asset_transaction() {
        let kp_sender = keys([0; 32]).pop().unwrap();

        let dummy_batch_digest = BatchDigest::new([0; DIGEST_LEN]);

        let transaction = TransactionVariant::CreateAssetTransaction(CreateAssetRequest::new(
            kp_sender.public().clone(),
            dummy_batch_digest,
        ));

        let transaction_digest = transaction.digest();
        let signed_digest = kp_sender.sign(transaction_digest.to_string().as_bytes());

        let signed_transaction =
            TransactionRequest::new(transaction.clone(), signed_digest.clone());

        // check valid signature
        signed_transaction.verify_transaction().unwrap();

        let sender_pub_key = kp_sender.public().clone();

        let signed_transaction_payload_matched = match signed_transaction.get_transaction_payload()
        {
            TransactionVariant::CreateAssetTransaction(r) => r,
            _ => {
                panic!("An unexpected error occurred while reading the payment transaction");
            }
        };

        // verify deterministic hashing
        let transaction_hash_0 = transaction.digest();
        let transaction_hash_1 = transaction.digest();
        assert!(
            transaction_hash_0 == transaction_hash_1,
            "hashes appears to have violated determinism"
        );

        assert!(
            *signed_transaction.get_sender() == sender_pub_key,
            "transaction sender does not match transaction input"
        );
        assert!(
            *signed_transaction_payload_matched.get_sender() == sender_pub_key,
            "transaction payload sender does not match transaction input"
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
                _ => {
                    panic!("An unexpected error occurred while reading the payment transaction");
                }
            };

        let matched_transaction_payload = match signed_transaction.get_transaction_payload() {
            TransactionVariant::PaymentTransaction(r) => r,
            _ => {
                panic!("An unexpected error occurred while reading the payment transaction");
            }
        };

        // verify transactions
        let transaction_hash_0 = signed_transaction.get_transaction_payload().digest();
        let transaction_hash_1 = signed_transaction_deserialized
            .get_transaction_payload()
            .digest();
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
            *matched_transaction_payload.get_sender()
                == *matched_transaction_payload_deserialized.get_sender(),
            "transaction sender does not match transction input"
        );
        assert!(
            *matched_transaction_payload.get_receiver()
                == *matched_transaction_payload_deserialized.get_receiver(),
            "transaction to does not match transction input"
        );
    }
}
