//!
//! The transaction class is responsible for parsing client interactions
//! each valid transaction corresponds to a unique state transition within
//! the space of allowable blockchain transitions
//!
use crate::{AccountKeyPair, AccountPubKey, AccountSignature, BatchDigest};
use blake2::{digest::Update, VarBlake2b};
use crypto::{traits::ToFromBytes, Digest, Hash, Verifier, DIGEST_LEN};
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Debug};
type AssetId = u64;
/// A valid payment transaction causes a state transition inside of
/// the BankController object, e.g. it creates a fund transfer from
/// User A to User B provided User A has sufficient funds
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PaymentRequest {
    // storing from here is not redundant as from may not equal sender
    // e.g. we are preserving the possibility of adding re-key functionality
    from: AccountPubKey,
    to: AccountPubKey,
    asset_id: AssetId,
    amount: u64,
    // it is necessary to pass a recent block hash to make sure that a transaction cannot
    // be duplicated, moreover it is used to gaurantee that a submitted transaction was
    // created within a well designated lookback, TODO - implement such checks in pipeline
    recent_batch_digest: BatchDigest,
}
impl PaymentRequest {
    pub fn new(
        from: AccountPubKey,
        to: AccountPubKey,
        asset_id: AssetId,
        amount: u64,
        recent_batch_digest: BatchDigest,
    ) -> Self {
        PaymentRequest {
            from,
            to,
            asset_id,
            amount,
            recent_batch_digest,
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

    pub fn get_recent_batch_digest(&self) -> &BatchDigest {
        &self.recent_batch_digest
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransactionVariant {
    PaymentTransaction(PaymentRequest),
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
                    hasher.update(payment.get_from().0.to_bytes());
                    hasher.update(payment.get_to().0.as_bytes());
                    hasher.update(payment.get_asset_id().to_le_bytes());
                    hasher.update(payment.get_amount().to_le_bytes());
                    // can we avoid turning into a string first?
                    hasher.update(payment.get_recent_batch_digest().to_string().as_bytes());
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

    pub fn deserialize(byte_vec: Vec<u8>) -> Result<Self, TransactionRequestError> {
        match bincode::deserialize(&byte_vec[..]) {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(TransactionRequestError::Deserialization(err)) }
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TransactionRequestError> {
        match bincode::serialize(&self) {
            Ok(result) => { Ok(result) }
            Err(err) => { Err(TransactionRequestError::Serialization(err)) }
        }
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

    pub fn verify_transaction(&self) -> Result<(), TransactionRequestError> {
        let transaction_digest = self.transaction_payload.digest();

        match &self.transaction_payload {
            TransactionVariant::PaymentTransaction(r) => {
                // for now there is no logic that supports re-keys, so we require sender matches payload
                if r.get_from().as_bytes() != self.sender.as_bytes() {
                    return Err(TransactionRequestError::InvalidSender(
                        "Sender does not match from field".to_string(),
                    ));
                }
            }
        };

        match self.sender.verify(
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

        TransactionRequest::new(transaction, kp_sender.public().clone(), signed_digest)
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

        let signed_transaction = TransactionRequest::new(
            transaction.clone(),
            kp_sender.public().clone(),
            signed_digest.clone(),
        );

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
