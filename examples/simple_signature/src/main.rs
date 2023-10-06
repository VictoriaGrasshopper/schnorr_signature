use schnorr_signature::keys_management::KeyPair;
use schnorr_signature::schnorr_single_signature::SchnorrSignature;
fn main() {
    // Create participant keys and nonce
    let keys = KeyPair::create();

    // Message to be signed
    let message = "Hello World".to_string();

    // Signature generation
    let signature = SchnorrSignature::sign(&message, &keys);

    // Verification of the signature
    let verification_result = signature.verify(keys.public_key, &message);

    assert!(verification_result);
}
