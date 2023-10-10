use rand_core::OsRng;
use schnorr_signature::keys_management::KeyPair;
use schnorr_signature::schnorr_single_signature::SchnorrSignature;

fn main() {
    let csprng = OsRng;
    // Create participant keys and nonce
    let keys = KeyPair::create(csprng);

    // Message to be signed
    let message = "Hello World";

    // Signature generation
    let signature = SchnorrSignature::sign(&message, &keys, csprng);

    // Verification of the signature
    let result = signature.verify(keys.get_public_key(), &message);

    println!("Verification result: {:?}", result);
    assert!(result);
}
