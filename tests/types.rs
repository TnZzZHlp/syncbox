use syncbox::types::KnownPeers;

#[test]
fn endpoint_collection_preserves_known_peer_validation() {
    let endpoint = iroh::SecretKey::from_bytes(&[74; 32]).public();
    let mut valid = KnownPeers::empty();
    valid.add_or_touch(&endpoint, 1);
    assert_eq!(valid.endpoint_ids().unwrap(), vec![endpoint]);
    let mut duplicate = valid.clone();
    duplicate.peers.push(duplicate.peers[0].clone());
    let mut malformed = valid.clone();
    malformed.peers[0].endpoint_id = "invalid".to_owned();
    let mut uppercase = valid.clone();
    uppercase.peers[0].endpoint_id.make_ascii_uppercase();
    let mut wrong_version = valid.clone();
    wrong_version.format_version = u16::MAX;
    let mut oversized = valid.clone();
    oversized.peers.resize(257, valid.peers[0].clone());
    for peers in [duplicate, malformed, uppercase, wrong_version, oversized] {
        let expected = peers.validate().unwrap_err().to_string();
        let actual = peers.endpoint_ids().unwrap_err().to_string();
        assert_eq!(actual, expected);
    }
}
