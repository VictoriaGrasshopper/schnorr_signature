use crate::keys_management::KeyPair;
use crate::rand_nonce::RandomNonce;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use secrecy::ExposeSecret;
use secrecy::Secret;
use sha2::Digest;
use sha2::Sha512;

// Aggregates a vector of public keys into a single public key.
// It computes:
// X = sum of all H(L||Xi)Xi
// where:
// - L = hash of all concatenated public key bytes
// - Xi = public key i
// - H(L||Xi) = hash of L concatenated with Xi
//
// This allows multiple parties to jointly create a public key for a single "virtual" participant.
//
// Inputs:
// - public_keys: Vector of RistrettoPoints, the public keys to aggregate
//
// Returns:
// - The aggregated public key as a RistrettoPoint
pub fn aggregate_public_keys(public_keys: &Vec<RistrettoPoint>) -> RistrettoPoint {
    // Ensure there are public keys to aggregate
    if public_keys.is_empty() {
        panic!("No public keys provided for aggregation.");
    };

    let cap_l = calc_cap_l(public_keys);

    let mut hashes_lxii_mul_xi = Vec::new();
    for pub_key in public_keys {
        hashes_lxii_mul_xi.push(calc_hash_lxi(cap_l, pub_key) * pub_key);
    }

    hashes_lxii_mul_xi.iter().sum()
}

// Computes H(L||Xi) which is the used in aggregate_public_keys(..) function
//
// Inputs:
// - cap_l: L value
// - cap_xi: Public key Xi to hash
//
// Returns:
// - H(L||Xi) as a Scalar
fn calc_hash_lxi(cap_l: Scalar, cap_xi: &RistrettoPoint) -> Scalar {
    let cap_l_bytes = cap_l.as_bytes();
    let cap_xi_bytes = cap_xi.compress().to_bytes();

    let mut concatenated_bytes = Vec::new();
    concatenated_bytes.extend_from_slice(cap_l_bytes);
    concatenated_bytes.extend_from_slice(&cap_xi_bytes);

    Scalar::hash_from_bytes::<Sha512>(&concatenated_bytes)
}

// Computes L by hashing the concatenation of all public key bytes
//
// Inputs:
// - public_keys: Vector of public keys
//
// Returns:
// - L value as a Scalar
pub fn calc_cap_l(public_keys: &Vec<RistrettoPoint>) -> Scalar {
    // Convert each public key to compressed bytes and concatenate them
    let mut concatenated_bytes = Vec::new();
    for public_key in public_keys {
        let compressed_bytes = public_key.compress().to_bytes();
        concatenated_bytes.extend_from_slice(&compressed_bytes);
    }
    // Hash the concatenated bytes using SHA-512
    let cap_l = Scalar::hash_from_bytes::<Sha512>(&concatenated_bytes);

    // Clear the concatenated_bytes vector to avoid unintentional data leakage
    concatenated_bytes.iter_mut().for_each(|byte| *byte = 0);

    cap_l
}

// Computes H(X||R||m) used in the signing equation
//
// Inputs:
// - cap_x: Aggregated public key X, compressed
// - cap_r: Aggregated nonce R
// - message: Message m being signed
//
// Returns:
// - H(X||R||m) as a Scalar
pub fn calc_hash_xrm(
    cap_x: &CompressedRistretto,
    cap_r: &RistrettoPoint,
    message: &String,
) -> Scalar {
    let cap_r_compressed = cap_r.compress();

    let message_hash_bytes = Sha512::digest(message.as_bytes());
    let cap_r_bytes = cap_r_compressed.as_bytes();
    let cap_x_bytes = cap_x.as_bytes();

    let mut concatenated_bytes = Vec::new();
    concatenated_bytes.extend_from_slice(cap_r_bytes);
    concatenated_bytes.extend_from_slice(cap_x_bytes);
    concatenated_bytes.extend_from_slice(&message_hash_bytes);

    Scalar::hash_from_bytes::<Sha512>(&concatenated_bytes)
}

// Sums a vector of nonce public keys (Ri) into a single public nonce key (R)
//
// Inputs:
// - nonces: Vector of RistrettoPoints, the nonce public keys
//
// Returns:
// - The sum of the nonces as a RistrettoPoint
pub fn aggregate_nonces(nonces: &Vec<RistrettoPoint>) -> RistrettoPoint {
    // Ensure there are public keys to aggregate
    if nonces.is_empty() {
        panic!("No nonce provided for aggregation.");
    };

    let cap_r: RistrettoPoint = nonces.iter().sum();

    cap_r
}

// Computes a signature "share" (partial signature)
// si = ri + H(X,R,m)H(L,Xi)xi
//
// Inputs:
// - message: Message m to sign
// - keys: Signer's keypair
// - r_private: Signer's nonce ri
// - cap_x: Aggregated public key X
// - cap_r: Aggregated nonce R
// - cap_l: Aggregated L value
//
// Returns:
// - Partial signature component si
pub fn partial_signature(
    message: &String,
    keys: &KeyPair,
    r_private: &Secret<Scalar>,
    cap_x: &RistrettoPoint,
    cap_r: &RistrettoPoint,
    cap_l: Scalar,
) -> Scalar {
    let cap_x_compressed: CompressedRistretto = cap_x.compress();
    let hash_xrm = calc_hash_xrm(&cap_x_compressed, cap_r, message);
    let hash_lxi = calc_hash_lxi(cap_l, &keys.public_key);

    let s = r_private.expose_secret() + hash_xrm * hash_lxi * keys.private_key.expose_secret();
    s
}

// Sums the partial signatures into the full signature s
//
// Inputs:
// - partial_signatures: Vector of partial signature components si
//
// Returns:
// - Final signature s as a Scalar
pub fn aggregate_s(partial_signatures: &Vec<Scalar>) -> Scalar {
    let mut s: Scalar = Scalar::ZERO;
    for partial_signature in partial_signatures {
        s += partial_signature;
    }
    s
}

// Verifies the signature (works for both partial signature and aggregated signature) using the equation:
// sG = R + H(X,R,m)X
//
// Inputs:
// - cap_x: Aggregated public key X
// - cap_r: Aggregated nonce R
// - message: Signed message m
// - s: Signature to verify
//
// Returns:
// - true if signature is valid, false otherwise
pub fn verify_signature(
    cap_x: &RistrettoPoint,
    cap_r: &RistrettoPoint,
    message: &String,
    s: Scalar,
) -> bool {
    let cap_x_compressed = cap_x.compress();
    let hash_xrm = calc_hash_xrm(&cap_x_compressed, cap_r, message);
    let left = s * RISTRETTO_BASEPOINT_POINT;
    let right = cap_r + hash_xrm * cap_x;

    left == right
}

pub fn test_valid_signature_with_n_parties(n: usize) -> bool {
    // Create empty vectors to store keys and nonces
    let mut key_pairs = Vec::new();
    let mut nonces = Vec::new();

    // Create n key pairs and nonces
    for _ in 0..n {
        let keys = KeyPair::create();
        let nonce = RandomNonce::new_rand();
        key_pairs.push(keys);
        nonces.push(nonce);
    }

    // Message to be signed
    let message = "Hello World".to_string();

    // Create vectors for public keys and nonce public keys
    let pkeys: Vec<RistrettoPoint> = key_pairs.iter().map(|keys| keys.public_key).collect();
    let nonce_pkeys: Vec<RistrettoPoint> = nonces.iter().map(|nonce| nonce.r_public).collect();

    // Aggregate public keys and nonces
    let aggregated_pkeys = aggregate_public_keys(&pkeys);
    let aggregated_nonces = aggregate_nonces(&nonce_pkeys);

    // Calculate cap_l
    let cap_l = calc_cap_l(&pkeys);

    // Create and aggregate partial signatures for each participant
    let mut partial_signatures = Vec::new();
    for i in 0..n {
        let nonce_clone = *nonces[i].r_private.expose_secret();
        let partial_signature = partial_signature(
            &message,
            &key_pairs[i],
            &Secret::new(nonce_clone),
            &aggregated_pkeys,
            &aggregated_nonces,
            cap_l,
        );
        partial_signatures.push(partial_signature);
    }

    // Aggregate partial signatures
    let aggregated_s = aggregate_s(&partial_signatures);

    // Verify the aggregated signature
    verify_signature(
        &aggregated_pkeys,
        &aggregated_nonces,
        &message,
        aggregated_s,
    )
}

#[derive(Debug)]
pub struct SchnorrMuSig {
    pub r: CompressedRistretto,
    pub s: Scalar,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_single_musig_signature() {
        assert!(test_valid_signature_with_n_parties(1));
    }

    #[test]
    fn test_multiple_musig_signature() {
        assert!(test_valid_signature_with_n_parties(100));
    }

    #[test]
    fn test_invalid_signature() {
        // Create participant keys and nonce
        let keys = KeyPair::create();
        let nonce = RandomNonce::new_rand();

        // Message to be signed
        let message = "Hello World".to_string();
        let invalid_message = "Send 0.000001 BTC to Bob".to_string();

        // Sets for aggregation of public keys and nonce
        let pkeys = vec![keys.public_key];
        let nonces = vec![nonce.r_public];

        let aggregated_pkeys = aggregate_public_keys(&pkeys);
        let aggregated_nonces = aggregate_nonces(&nonces);

        let cap_l = calc_cap_l(&pkeys);

        let partial_signature = partial_signature(
            &message,
            &keys,
            &nonce.r_private,
            &aggregated_pkeys,
            &aggregated_nonces,
            cap_l,
        );

        let aggregated_s = aggregate_s(&vec![partial_signature]);
        let verification_result = verify_signature(
            &aggregated_pkeys,
            &aggregated_nonces,
            &invalid_message,
            aggregated_s,
        );

        assert!(!verification_result)
    }

    #[test]
    fn test_valid_aggregated_public_keys() {
        let private_key1 = Secret::new(Scalar::from_bytes_mod_order([
            67, 56, 179, 96, 248, 67, 116, 105, 5, 4, 149, 252, 197, 175, 198, 21, 77, 164, 143,
            146, 203, 200, 203, 180, 177, 184, 214, 231, 120, 91, 171, 1,
        ]));
        let private_key2 = Secret::new(Scalar::from_bytes_mod_order([
            36, 207, 100, 184, 150, 122, 252, 87, 46, 222, 253, 26, 133, 115, 104, 94, 23, 28, 72,
            78, 84, 212, 2, 20, 191, 14, 245, 236, 157, 65, 56, 0,
        ]));

        let keys1 = KeyPair::create_from_private_key(private_key1);
        let keys2 = KeyPair::create_from_private_key(private_key2);

        let public_keys = vec![keys1.public_key, keys2.public_key];
        let aggregated_public_keys = aggregate_public_keys(&public_keys).compress();

        let expected_aggregated_pkeys = CompressedRistretto::from_slice(&[
            2, 110, 128, 142, 32, 157, 151, 88, 27, 46, 14, 126, 228, 147, 133, 241, 105, 43, 224,
            243, 11, 73, 216, 45, 212, 162, 203, 152, 136, 149, 46, 122,
        ])
        .unwrap();

        assert!(aggregated_public_keys == expected_aggregated_pkeys);
    }
    #[test]
    fn test_invalid_aggregated_public_keys() {
        let private_key1 = Secret::new(Scalar::from_bytes_mod_order([
            67, 56, 179, 96, 248, 67, 116, 105, 5, 4, 149, 252, 197, 175, 198, 21, 77, 164, 143,
            146, 203, 200, 203, 180, 177, 184, 214, 231, 120, 91, 171, 1,
        ]));
        let private_key2 = Secret::new(Scalar::from_bytes_mod_order([
            36, 207, 100, 184, 150, 122, 252, 87, 46, 222, 253, 26, 133, 115, 104, 94, 23, 28, 72,
            78, 84, 212, 2, 20, 191, 14, 245, 236, 157, 65, 56, 0,
        ]));

        let keys1 = KeyPair::create_from_private_key(private_key1);
        let keys2 = KeyPair::create_from_private_key(private_key2);

        let public_keys = vec![keys1.public_key, keys2.public_key];
        let aggregated_public_keys = aggregate_public_keys(&public_keys).compress();

        let expected_aggregated_pkeys = CompressedRistretto::from_slice(&[
            2, 111, 128, 142, 32, 157, 151, 88, 27, 46, 14, 126, 228, 147, 133, 241, 105, 43, 224,
            243, 11, 73, 216, 45, 212, 162, 203, 152, 136, 149, 46, 122,
        ])
        .unwrap();

        assert!(!(aggregated_public_keys == expected_aggregated_pkeys));
    }
}
