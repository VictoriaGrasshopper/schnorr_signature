#![no_main]

use libfuzzer_sys::fuzz_target;

use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use schnorr_signature::aggregator::Aggregator;
use schnorr_signature::party::Party;
use secrecy::Secret;
use sha2::Sha512;

fuzz_target!(|data: &[u8]| {
    // Message to be signed
    let message_to_sign = "Hello world".to_string();

    // Randomness source
    let mut seeded_rng = StdRng::seed_from_u64(123);

    let private_key = Secret::new(Scalar::hash_from_bytes::<Sha512>(data));

    // The first round of public keys aggregation
    let (party, pub_key_message) = Party::new_from_private_key(private_key, &message_to_sign);
    let aggregator = Aggregator::new(1, &message_to_sign).expect("Error");
    let (aggregator, aggregated_public_key) = aggregator
        .aggregate_public_keys(vec![pub_key_message])
        .expect("Error");

    // The second round of public nonces aggregation
    let (party, nonce_message) = party.generate_nonce(aggregated_public_key, seeded_rng);
    let (aggregator, agg_nonce_message) = aggregator
        .aggregate_nonces(vec![nonce_message])
        .expect("Error");

    // The third round of signatures aggregation
    let (_party, part_sig_message) = party.generate_partial_signature(agg_nonce_message);
    let aggregator = aggregator
        .aggregate_signatures(vec![part_sig_message])
        .expect("Error");
    let (aggregator, _agg_sig_message) = aggregator.calc_aggregated_signature().expect("Error");
    let result = aggregator.verify_signature().expect("Error");

    assert!(result);
});
