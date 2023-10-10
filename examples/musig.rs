use rand_core::OsRng;
use schnorr_signature::aggregator::Aggregator;
use schnorr_signature::party::Party;
fn main() {
    // Message to be signed
    let message_to_sign = "Hello World".to_string();

    // Randomness source
    let csprng = OsRng;

    // The first round of public keys aggregation
    let (party, pub_key_message) = Party::new(&message_to_sign, csprng);
    let aggregator = Aggregator::new(1, &message_to_sign).expect("Error");
    let (aggregator, aggregated_public_key) = aggregator
        .aggregate_public_keys(vec![pub_key_message])
        .expect("Error");

    // The second round of public nonces aggregation
    let (party, nonce_message) = party.generate_nonce(aggregated_public_key, csprng);
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

    println!("Verification result: {:?}", result);
    assert!(result);
}
