// The `messages` module contains the API for the messages passed between the parties and the aggregator
// in an aggregated multiparty computation protocol.
use crate::schnorr_musig::musig_math::verify_signature;

use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PublicKey {
    pub public_key: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct AggregatedPublicKeyAndHashMessage {
    pub public_key: RistrettoPoint,
    pub cap_l: Scalar,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct RandomNonceMessage {
    pub r_public: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct AggregatedRandomNonce {
    pub r_public: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PartialSignature {
    pub partial_signature: Scalar,
}

impl PartialSignature {
    pub(super) fn verify_share(
        &self,
        cap_x: &RistrettoPoint,
        cap_r: &RistrettoPoint,
        message: &String,
    ) -> Result<(), String> {
        if verify_signature(cap_x, cap_r, message, self.partial_signature) {
            Ok(())
        } else {
            Err(format!("The partial signature {:?} is not valid", self))
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct AggregatedSignature {
    pub signature_r: RistrettoPoint,
    pub signature_s: Scalar,
}
