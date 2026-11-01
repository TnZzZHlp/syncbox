use syncbox::types::KnownPeers;

#[test]
fn batch_peer_merge_preserves_existing_timestamps_and_refreshes_duplicates() {
    let existing = iroh::SecretKey::from_bytes(&[75; 32]).public();
    let added = iroh::SecretKey::from_bytes(&[76; 32]).public();
    let mut peers = KnownPeers::empty();
    peers.add_or_touch(&existing, 10);
    peers.merge_endpoint_ids([added, existing, added], 20);
    assert_eq!(peers.peers.len(), 2);
    assert!(peers.peers[0].endpoint_id < peers.peers[1].endpoint_id);
    let old_record = peers
        .peers
        .iter()
        .find(|peer| peer.endpoint_id == existing.to_string())
        .unwrap();
    assert_eq!(old_record.added_at_ms, 10);
    assert_eq!(old_record.last_seen_at_ms, Some(20));
    let new_record = peers
        .peers
        .iter()
        .find(|peer| peer.endpoint_id == added.to_string())
        .unwrap();
    assert_eq!(new_record.added_at_ms, 20);
    assert_eq!(new_record.last_seen_at_ms, Some(20));
}

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
