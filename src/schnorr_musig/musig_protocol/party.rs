/// This module defines a Party struct representing a participant in a Schnorr-Musig
/// multi-signature scheme. Parties can progress through different states, generate
/// nonces, compute partial signatures, and finalize the aggregated signature.
use super::protocol_messages::*;
use crate::keys_management::KeyPair;
use crate::rand_nonce::RandomNonce;
use crate::schnorr_musig::musig_math::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use secrecy::Secret;
use std::borrow::Cow;
use std::marker::PhantomData;

/// Party struct, which manages the role of a participant in the scheme.
pub struct Party<'a, S: PartyState> {
    keys: KeyPair,
    message: Cow<'a, str>,
    general_public_key: Option<RistrettoPoint>,
    cap_l: Option<Scalar>,
    nonce: Option<RandomNonce>,
    general_nonce: Option<RistrettoPoint>,
    partial_signature: Option<Scalar>,
    aggregated_signature: Option<Scalar>,
    state: PhantomData<S>,
}

/// Represents the possible states of a Party.
pub trait PartyState {}
/// Initial state when creating a new Party.
pub struct NewParty;
/// State for generating random nonces.
pub struct RandomNonceGeneration;
/// State for computing partial signatures.
pub struct PartialSignatureComputation;
/// State when awaiting the aggregated signature.
pub struct AwaitingAggregatedSignature;
/// State when the party's role is finalized.
pub struct PartyFinalized;

impl PartyState for NewParty {}
impl PartyState for RandomNonceGeneration {}
impl PartyState for PartialSignatureComputation {}
impl PartyState for AwaitingAggregatedSignature {}
impl PartyState for PartyFinalized {}

impl<S: PartyState> Party<'_, S> {}

impl<'a> Party<'a, NewParty> {
    /// Create a new Party instance.
    ///
    /// # Arguments
    ///
    /// * `message` - A reference to the message to be signed.
    ///
    /// Returns a tuple containing:
    /// 1. A Party in the "RandomNonceGeneration" state.
    /// 2. A PublicKey associated with the Party's public key.
    pub fn new<R>(
        message: impl Into<Cow<'a, str>>,
        rng: R,
    ) -> (Party<'a, RandomNonceGeneration>, PublicKey)
    where
        R: rand::CryptoRng + rand::RngCore,
    {
        let keys = KeyPair::create(rng);
        let public_key = keys.public_key;
        (
            Party {
                keys,
                message: message.into(),
                general_public_key: None,
                cap_l: None,
                nonce: None,
                general_nonce: None,
                partial_signature: None,
                aggregated_signature: None,
                state: PhantomData::<RandomNonceGeneration>,
            },
            PublicKey { public_key },
        )
    }

    /// Create a new Party instance from a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The Party's private key.
    /// * `message` - A reference to the message to be signed.
    ///
    /// Returns a tuple containing:
    /// 1. A Party in the "RandomNonceGeneration" state.
    /// 2. A PublicKey associated with the Party's public key.
    pub fn new_from_private_key(
        private_key: Secret<Scalar>,
        message: impl Into<Cow<'a, str>>,
    ) -> (Party<'a, RandomNonceGeneration>, PublicKey) {
        let keys = KeyPair::create_from_private_key(private_key);
        let public_key = keys.public_key;
        (
            Party {
                keys,
                message: message.into(),
                general_public_key: None,
                cap_l: None,
                nonce: None,
                general_nonce: None,
                partial_signature: None,
                aggregated_signature: None,
                state: PhantomData::<RandomNonceGeneration>,
            },
            PublicKey { public_key },
        )
    }
}

impl Party<'_, RandomNonceGeneration> {
    /// Generate a random nonce and prepare for the next state.
    ///
    /// # Arguments
    ///
    /// * `agg_pubkey_and_hash_message` - Aggregated public key and hash message.
    ///
    /// Returns a tuple containing:
    /// 1. A Party in the "PartialSignatureComputation" state.
    /// 2. A RandomNonceMessage containing the random nonce.
    pub fn generate_nonce<R>(
        &self,
        agg_pubkey_and_hash_message: AggregatedPublicKeyAndHashMessage,
        rng: R,
    ) -> (Party<PartialSignatureComputation>, RandomNonceMessage)
    where
        R: rand::CryptoRng + rand::RngCore,
    {
        let nonce = RandomNonce::new_rand(rng);
        (
            Party {
                keys: self.keys.clone(),
                message: self.message.clone(),
                general_public_key: Some(agg_pubkey_and_hash_message.public_key),
                cap_l: Some(agg_pubkey_and_hash_message.cap_l),
                nonce: Some(nonce.clone()),
                general_nonce: None,
                partial_signature: None,
                aggregated_signature: None,
                state: PhantomData::<PartialSignatureComputation>,
            },
            RandomNonceMessage {
                r_public: nonce.r_public,
            },
        )
    }
}

impl Party<'_, PartialSignatureComputation> {
    /// Generate a partial signature and prepare for the next state.
    ///
    /// # Arguments
    ///
    /// * `general_nonce` - Aggregated random nonce.
    ///
    /// Returns a tuple containing:
    /// 1. A Party in the "AwaitingAggregatedSignature" state.
    /// 2. A PartialSignature containing the partial signature.
    pub fn generate_partial_signature(
        &self,
        general_nonce: AggregatedRandomNonce,
    ) -> (Party<AwaitingAggregatedSignature>, PartialSignature) {
        let nonce = self.nonce.clone().unwrap();
        let partial_signature = partial_signature(
            self.message.clone(),
            &self.keys,
            &nonce.r_private,
            self.general_public_key.as_ref().unwrap(),
            &general_nonce.r_public,
            self.cap_l.unwrap(),
        );
        (
            Party {
                keys: self.keys.clone(),
                message: self.message.clone(),
                general_public_key: self.general_public_key,
                cap_l: self.cap_l,
                nonce: Some(nonce),
                general_nonce: Some(general_nonce.r_public),
                partial_signature: None,
                aggregated_signature: None,
                state: PhantomData::<AwaitingAggregatedSignature>,
            },
            PartialSignature { partial_signature },
        )
    }
}

impl Party<'_, AwaitingAggregatedSignature> {
    /// Set the aggregated signature and prepare for the final state.
    ///
    /// # Arguments
    ///
    /// * `aggregated_signature` - The aggregated signature.
    ///
    /// Returns a Party in the "PartyFinalized" state.
    pub fn set_aggregated_signature(&self, aggregated_signature: Scalar) -> Party<PartyFinalized> {
        Party {
            keys: self.keys.clone(),
            message: self.message.clone(),
            general_public_key: self.general_public_key,
            cap_l: self.cap_l,
            nonce: self.nonce.clone(),
            general_nonce: self.general_nonce,
            partial_signature: self.partial_signature,
            aggregated_signature: Some(aggregated_signature),
            state: PhantomData::<PartyFinalized>,
        }
    }
}

impl Party<'_, PartyFinalized> {
    /// Get the aggregated signature.
    ///
    /// Returns an AggregatedSignature containing the aggregated signature.

    pub fn get_signature(&self) -> AggregatedSignature {
        AggregatedSignature {
            signature_r: self.general_nonce.unwrap(),
            signature_s: self.aggregated_signature.unwrap(),
        }
    }

    /// Verify the aggregated signature.
    ///
    /// Returns a Result indicating success or an error message if the verification fails.

    pub fn verify_signature(&self) -> Result<(), String> {
        if verify_signature(
            &self.general_public_key.unwrap(),
            &self.general_nonce.unwrap(),
            self.message.clone(),
            self.aggregated_signature.unwrap(),
        ) {
            Ok(())
        } else {
            Err(format!(
                "The partial signature {:?} is not valid",
                (self.general_nonce, self.aggregated_signature)
            ))
        }
    }
}
