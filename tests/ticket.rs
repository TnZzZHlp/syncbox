use iroh::SecretKey;

use syncbox::ticket::{ShareTicket, TICKET_PREFIX};
use syncbox::types::{ShareId, ShareSecret};

#[test]
fn ticket_round_trip_is_canonical_and_deterministic() {
    let peer = SecretKey::from_bytes(&[7; 32]).public();
    let ticket = ShareTicket::new(
        ShareId([3; 32]),
        ShareSecret::from_bytes([4; 32]),
        vec![peer],
    )
    .unwrap();
    let encoded = ticket.encode().unwrap();
    assert!(encoded.starts_with(TICKET_PREFIX));
    let parsed = ShareTicket::parse(&encoded).unwrap();
    assert_eq!(parsed.share_id, ticket.share_id);
    assert_eq!(parsed.share_secret, ticket.share_secret);
    assert_eq!(parsed.initial_peers[0], peer);
    assert_eq!(parsed.encode().unwrap(), encoded);
}

#[test]
fn ticket_rejects_padding_and_checksum_tampering() {
    let peer = SecretKey::from_bytes(&[8; 32]).public();
    let ticket = ShareTicket::new(
        ShareId([5; 32]),
        ShareSecret::from_bytes([6; 32]),
        vec![peer],
    )
    .unwrap()
    .encode()
    .unwrap();
    assert!(ShareTicket::parse(&(ticket.clone() + "=")).is_err());
    let mut altered = ticket.into_bytes();
    let last = altered.len() - 1;
    altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
    assert!(ShareTicket::parse(std::str::from_utf8(&altered).unwrap()).is_err());
}

#[test]
fn ticket_canonicalizes_initial_peer_order() {
    let first = SecretKey::from_bytes(&[10; 32]).public();
    let second = SecretKey::from_bytes(&[11; 32]).public();
    let left = ShareTicket::new(
        ShareId([12; 32]),
        ShareSecret::from_bytes([13; 32]),
        vec![first, second],
    )
    .unwrap()
    .encode()
    .unwrap();
    let right = ShareTicket::new(
        ShareId([12; 32]),
        ShareSecret::from_bytes([13; 32]),
        vec![second, first],
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(left, right);
}
