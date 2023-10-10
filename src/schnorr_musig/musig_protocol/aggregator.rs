/// This module defines an Aggregator struct for aggregating signatures
/// from multiple parties in a Schnorr-Musig multi-signature scheme.
/// It allows parties to sequentially aggregate public keys, nonces,
/// and partial signatures, and finally compute the aggregated signature.
use super::protocol_messages::*;
use crate::schnorr_musig::musig_math::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::marker::PhantomData;

/// Aggregator struct, which manages the aggregation process.
pub struct Aggregator<'a, S: AggregationState> {
    parties_quantity: usize,
    message: &'a str,
    public_keys: Option<Vec<RistrettoPoint>>,
    general_public_key: Option<RistrettoPoint>,
    public_nonces: Option<Vec<RistrettoPoint>>,
    general_nonce: Option<RistrettoPoint>,
    partial_signatures: Option<Vec<Scalar>>,
    aggregated_signature: Option<Scalar>,
    state: PhantomData<S>,
}

use std::fmt::{Debug, Formatter};
impl<S: AggregationState> Debug for Aggregator<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aggregator")
            .field("message", &self.message)
            .field("general_public_key", &self.general_public_key)
            .field("general_nonce", &self.general_nonce)
            .field("aggregated_signature", &self.aggregated_signature)
            .finish()
    }
}

/// Represents the possible states of the Aggregator.
pub trait AggregationState {}

/// Initial state when creating a new Aggregator.
pub struct NewAggregator;

/// State when waiting for public keys from parties.
pub struct AwaitingPublicKeys;

/// State when waiting for public nonces from parties.
pub struct AwaitingPublicNonces;

/// State when waiting for partial signatures from parties.
pub struct AwaitingPartialSignatures;

/// State when calculating the aggregated signature.
pub struct CalculatingAggregatedSignature;

/// State when the aggregation process is finalized.
pub struct AggregationFinalized;

impl AggregationState for NewAggregator {}
impl AggregationState for AwaitingPublicKeys {}
impl AggregationState for AwaitingPublicNonces {}
impl AggregationState for AwaitingPartialSignatures {}
impl AggregationState for CalculatingAggregatedSignature {}
impl AggregationState for AggregationFinalized {}

impl<S: AggregationState> Aggregator<'_, S> {}

impl<'a> Aggregator<'a, NewAggregator> {
    /// Create a new Aggregator instance.
    ///
    /// # Arguments
    ///
    /// * `parties_quantity` - The number of parties involved in the aggregation.
    /// * `message` - A reference to the message being signed.
    ///
    /// Returns an `Ok` result with an Aggregator in the "AwaitingPublicKeys" state,
    /// or an `Err` result with a description if `parties_quantity` is 0.
    pub fn new(
        parties_quantity: usize,
        message: &'a str,
    ) -> Result<Aggregator<'a, AwaitingPublicKeys>, String> {
        if parties_quantity == 0 {
            return Err("Parties quantity cannot be 0.".to_string());
        }
        Ok(Aggregator {
            parties_quantity,
            message,
            public_keys: None,
            general_public_key: None,
            public_nonces: None,
            general_nonce: None,
            partial_signatures: None,
            aggregated_signature: None,
            state: PhantomData::<AwaitingPublicKeys>,
        })
    }

    /// Create a new Aggregator instance and skip the protocol steps by providing
    /// precomputed values such as public keys, nonces, and partial signatures.
    ///
    /// # Arguments
    ///
    /// * `parties_quantity` - The number of parties involved in the aggregation.
    /// * `message` - A reference to the message being signed.
    /// * `public_keys` - A vector of public keys from each party.
    /// * `general_public_key` - The aggregated public key.
    /// * `public_nonces` - A vector of public nonces from each party.
    /// * `general_nonce` - The aggregated public nonce.
    /// * `partial_signatures` - A vector of partial signatures from each party.
    ///
    /// Returns an `Ok` result with an Aggregator in the "CalculatingAggregatedSignature" state,
    /// or an `Err` result with a description if any of the quantities do not match.
    pub fn new_skip_the_protocol(
        parties_quantity: usize,
        message: &'a str,
        public_keys: Vec<RistrettoPoint>,
        general_public_key: RistrettoPoint,
        public_nonces: Vec<RistrettoPoint>,
        general_nonce: RistrettoPoint,
        partial_signatures: Vec<Scalar>,
    ) -> Result<Aggregator<'a, CalculatingAggregatedSignature>, String> {
        if parties_quantity == 0 {
            return Err("Parties quantity cannot be 0.".to_string());
        }

        // Verify that the quantities match
        if public_keys.len() != parties_quantity
            || public_nonces.len() != parties_quantity
            || partial_signatures.len() != parties_quantity
        {
            return Err(
                "Mismatched quantities of keys, nonces, or partial signatures.".to_string(),
            );
        }

        Ok(Aggregator {
            parties_quantity,
            message,
            public_keys: Some(public_keys),
            general_public_key: Some(general_public_key),
            public_nonces: Some(public_nonces),
            general_nonce: Some(general_nonce),
            partial_signatures: Some(partial_signatures),
            aggregated_signature: None,
            state: PhantomData::<CalculatingAggregatedSignature>,
        })
    }
}

impl Aggregator<'_, AwaitingPublicKeys> {
    /// Aggregate public keys from parties and prepare for the next state.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - A vector of public keys from each party.
    ///
    /// Returns a tuple containing:
    /// 1. An Aggregator in the "AwaitingPublicNonces" state.
    /// 2. An AggregatedPublicKeyAndHashMessage containing the aggregated public key
    ///    and a hash of the public keys.
    ///
    /// Returns an `Ok` result with the tuple, or an `Err` result with a description
    /// if the quantity of public keys does not match `parties_quantity`.
    pub fn aggregate_public_keys(
        &self,
        public_keys: Vec<PublicKey>,
    ) -> Result<
        (
            Aggregator<AwaitingPublicNonces>,
            AggregatedPublicKeyAndHashMessage,
        ),
        String,
    > {
        if public_keys.len() != self.parties_quantity {
            return Err("Mismatched quantities of public keys.".to_string());
        }
        let public_keys: Vec<RistrettoPoint> = public_keys
            .iter()
            .map(|public_key| public_key.public_key)
            .collect();
        let aggregated_public_key = aggregate_public_keys(&public_keys)?;

        Ok((
            Aggregator {
                parties_quantity: self.parties_quantity,
                message: self.message,
                public_keys: Some(public_keys.clone()),
                general_public_key: Some(aggregated_public_key),
                public_nonces: None,
                general_nonce: None,
                partial_signatures: None,
                aggregated_signature: None,
                state: PhantomData::<AwaitingPublicNonces>,
            },
            AggregatedPublicKeyAndHashMessage {
                public_key: aggregated_public_key,
                cap_l: calc_cap_l(&public_keys),
            },
        ))
    }
}

impl Aggregator<'_, AwaitingPublicNonces> {
    /// Aggregate public nonces from parties and prepare for the next state.
    ///
    /// # Arguments
    ///
    /// * `nonces` - A vector of public nonces from each party.
    ///
    /// Returns a tuple containing:
    /// 1. An Aggregator in the "AwaitingPartialSignatures" state.
    /// 2. An AggregatedRandomNonce containing the aggregated public nonce.
    ///
    /// Returns an `Ok` result with the tuple, or an `Err` result with a description
    /// if the quantity of nonces does not match `parties_quantity`.
    pub fn aggregate_nonces(
        &self,
        nonces: Vec<RandomNonceMessage>,
    ) -> Result<(Aggregator<AwaitingPartialSignatures>, AggregatedRandomNonce), String> {
        if nonces.len() != self.parties_quantity {
            return Err("Mismatched quantity of nonces.".to_string());
        }

        let nonces: Vec<RistrettoPoint> = nonces.iter().map(|nonce| nonce.r_public).collect();
        let aggregated_nonce = aggregate_nonces(&nonces)?;

        Ok((
            Aggregator {
                parties_quantity: self.parties_quantity,
                message: self.message,
                public_keys: self.public_keys.clone(),
                general_public_key: self.general_public_key,
                public_nonces: Some(nonces),
                general_nonce: Some(aggregated_nonce),
                partial_signatures: None,
                aggregated_signature: None,
                state: PhantomData::<AwaitingPartialSignatures>,
            },
            AggregatedRandomNonce {
                r_public: aggregated_nonce,
            },
        ))
    }
}

impl Aggregator<'_, AwaitingPartialSignatures> {
    /// Aggregate partial signatures from parties, verify them, and prepare for the next state.
    ///
    /// # Arguments
    ///
    /// * `partial_signatures` - A vector of partial signatures from each party.
    ///
    /// Returns an Aggregator in the "CalculatingAggregatedSignature" state.
    ///
    /// Returns an `Ok` result with the Aggregator, or an `Err` result with a description
    /// if the quantity of partial signatures does not match `parties_quantity` or if any
    /// of the partial signatures is invalid.
    pub fn aggregate_signatures(
        &self,
        partial_signatures: Vec<PartialSignature>,
    ) -> Result<Aggregator<CalculatingAggregatedSignature>, String> {
        if partial_signatures.len() != self.parties_quantity {
            return Err("Mismatched quantity of partial signatures.".to_string());
        }

        let mut partial_signatures_verified = Vec::new();
        for partial_signature in partial_signatures {
            if partial_signature
                .verify_share(
                    &self.general_public_key.unwrap(),
                    &self.general_nonce.unwrap(),
                    self.message,
                )
                .is_ok()
            {
                partial_signatures_verified.push(partial_signature.partial_signature)
            } else {
                return Err("Partial signature is invalid.".to_string());
            }
        }

        let public_keys = self.public_keys.clone();
        let nonces = self.public_nonces.clone();

        Ok(Aggregator {
            parties_quantity: self.parties_quantity,
            message: self.message,
            public_keys,
            general_public_key: self.general_public_key,
            public_nonces: nonces,
            general_nonce: self.general_nonce,
            partial_signatures: Some(partial_signatures_verified),
            aggregated_signature: None,
            state: PhantomData::<CalculatingAggregatedSignature>,
        })
    }
}

impl Aggregator<'_, CalculatingAggregatedSignature> {
    /// Calculate the aggregated signature and prepare for the next state.
    ///
    /// Returns a tuple containing:
    /// 1. An Aggregator in the "AggregationFinalized" state.
    /// 2. An AggregatedSignature containing the aggregated signature.
    ///
    /// Returns an `Ok` result with the tuple.
    pub fn calc_aggregated_signature(
        &self,
    ) -> Result<(Aggregator<AggregationFinalized>, AggregatedSignature), String> {
        let public_keys = self.public_keys.clone();
        let nonces = self.public_nonces.clone();
        let partial_signatures = self.partial_signatures.clone();
        let aggregated_signature = aggregate_s(partial_signatures.clone().unwrap())?;
        Ok((
            Aggregator {
                parties_quantity: self.parties_quantity,
                message: self.message,
                public_keys,
                general_public_key: self.general_public_key,
                public_nonces: nonces,
                general_nonce: self.general_nonce,
                partial_signatures,
                aggregated_signature: Some(aggregated_signature),
                state: PhantomData::<AggregationFinalized>,
            },
            AggregatedSignature {
                signature_r: self.general_nonce.unwrap(),
                signature_s: aggregated_signature,
            },
        ))
    }
}

impl Aggregator<'_, AggregationFinalized> {
    /// Get the aggregated signature.
    ///
    /// Returns an AggregatedSignature containing the aggregated signature.
    pub fn get_aggregated_signature(&self) -> AggregatedSignature {
        AggregatedSignature {
            signature_r: self.general_nonce.unwrap(),
            signature_s: self.aggregated_signature.unwrap(),
        }
    }

    /// Verify the aggregated signature.
    ///
    /// Returns true if the verification is successful; otherwise, false.
    pub fn verify_signature(&self) -> Result<bool, String> {
        Ok(verify_signature(
            &self.general_public_key.unwrap(),
            &self.general_nonce.unwrap(),
            self.message,
            self.aggregated_signature.unwrap(),
        ))
    }
}
