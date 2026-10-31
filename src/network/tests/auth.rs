use super::*;

#[test]
fn authentication_proof_is_bound_to_each_share() {
    let (config, client, server) = config();
    let proof = client_proof(&config, &client, &server, [7; 32]);
    let mut other = config;
    other.share_id = ShareId([8; 32]);
    assert_ne!(proof, client_proof(&other, &client, &server, [7; 32]));
}
