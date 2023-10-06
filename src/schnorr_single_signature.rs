use crate::keys_management::KeyPair;
use crate::rand_nonce::RandomNonce;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use secrecy::ExposeSecret;
use sha2::Sha512;

/// Schnorr signature structure: (R, s).
#[derive(Debug)]
pub struct SchnorrSignature {
    pub cap_r_compressed: CompressedRistretto,
    pub s: Scalar,
}

impl SchnorrSignature {
    /// Signs a message using a simple Schnorr signature scheme:
    /// (R,s) = (rG, r + H(X,R,m)x)
    ///
    /// # Arguments
    ///
    /// * `message` - The message to be signed.
    /// * `key_pair` - The key pair for signing.
    ///
    /// # Returns
    ///
    /// A SchnorrSignature struct containing `cap_r_compressed` and `s`.
    ///
    #[tracing::instrument(name = "Signing the message with Schnorr signature")]
    pub fn sign(message: &String, key_pair: &KeyPair) -> Self {
        let nonce = RandomNonce::new_rand();
        let hash_rpm = calc_hash_rpm(key_pair.public_key, nonce.r_public, message);
        let s = nonce.r_private.expose_secret() + hash_rpm * key_pair.private_key.expose_secret();

        SchnorrSignature {
            cap_r_compressed: nonce.r_public.compress(),
            s,
        }
    }

    /// Verifies a Schnorr signature using the following formula:
    /// sG = R + H(X,R,m)X
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to verify the signature.
    /// * `message` - The message that was signed.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    ///
    #[tracing::instrument(name = "Verifying the Schnorr signature")]
    pub fn verify(&self, public_key: RistrettoPoint, message: &String) -> bool {
        let r_public = self
            .cap_r_compressed
            .decompress()
            .expect("Failed to decompress R");
        let hash_rpm = calc_hash_rpm(public_key, r_public, message);

        let left = self.s * RISTRETTO_BASEPOINT_POINT;
        let right = r_public + hash_rpm * public_key;

        left.compress() == right.compress()
    }
}

/// Calculates the hash value of the concatenation of `public_key`, `R`, and `message`.
///
/// # Arguments
///
/// * `public_key` - The public key.
/// * `r_compressed` - The compressed point `r`.
/// * `message` - The message.
///
/// # Returns
///
/// The hash value as a `Scalar`.
///
#[tracing::instrument(name = "Calculating Hash(r||P||m) for the Schnorr signature")]
fn calc_hash_rpm(
    public_key: RistrettoPoint,
    r_compressed: RistrettoPoint,
    message: &String,
) -> Scalar {
    let nonce_compressed = r_compressed.compress();
    let nonce_bytes = nonce_compressed.as_bytes();
    let message_bytes = message.as_bytes();

    let public_key_compressed = public_key.compress();
    let public_key_bytes = public_key_compressed.as_bytes();

    let mut concatenated_bytes = Vec::new();
    concatenated_bytes.extend_from_slice(nonce_bytes);
    concatenated_bytes.extend_from_slice(public_key_bytes);
    concatenated_bytes.extend_from_slice(message_bytes);

    Scalar::hash_from_bytes::<Sha512>(&concatenated_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_valid_simple_signature() {
        // Create participant keys and nonce
        let keys = KeyPair::create();

        // Message to be signed
        let message = "Hello World".to_string();

        let signature = SchnorrSignature::sign(&message, &keys);

        let verification_result = signature.verify(keys.public_key, &message);

        assert!(verification_result);
    }
    #[test]
    fn test_invalid_simple_signature() {
        // Create participant keys and nonce
        let keys = KeyPair::create();

        // Message to be signed
        let message = "Hello World".to_string();
        let invalid_message = "Send 0.000001 BTC to Bob".to_string();

        let signature = SchnorrSignature::sign(&message, &keys);

        let verification_result = signature.verify(keys.public_key, &invalid_message);

        assert!(!verification_result);
    }
}
