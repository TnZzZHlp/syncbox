use super::*;

#[test]
fn cached_hlc_authors_still_reject_invalid_keys() {
    let valid = HlcTimestamp {
        wall_ms: 1,
        counter: 0,
        author: *SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
    };
    assert!(validate_timestamp(&valid).is_ok());
    assert!(validate_timestamp(&valid).is_ok());
    let invalid_author = (0_u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| EndpointId::from_bytes(bytes).is_err())
        .expect("some compressed points are invalid");
    let invalid = HlcTimestamp {
        author: invalid_author,
        ..valid
    };
    assert!(validate_timestamp(&invalid).is_err());
    assert!(validate_timestamp(&invalid).is_err());
    for index in 0_u64..300 {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        let author = HlcTimestamp {
            author: *SecretKey::from_bytes(&seed).public().as_bytes(),
            ..valid
        };
        validate_timestamp(&author).unwrap();
    }
    VALID_AUTHORS.with(|authors| assert_eq!(authors.borrow().len(), MAX_CACHED_AUTHORS));
    assert!(validate_timestamp(&invalid).is_err());
}

#[test]
fn sync_digest_ignores_local_scan_metadata() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("config.txt"), "one").unwrap();
    let share_id = ShareId([12; 32]);
    let endpoint = SecretKey::from_bytes(&[13; 32]).public();
    let scanned = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    let expected = scanned.manifest.sync_digest(share_id).unwrap();
    assert_eq!(scanned.manifest.sync_digest_after_validation(), expected);
    let mut local_metadata = scanned.manifest;
    local_metadata.scanned_at_ms += 1;
    local_metadata
        .entries
        .get_mut("config.txt")
        .unwrap()
        .modified_at_ns += 1;

    assert_eq!(local_metadata.sync_digest(share_id).unwrap(), expected);

    local_metadata.entries.get_mut("config.txt").unwrap().sha256 = "0".repeat(64);
    assert_ne!(local_metadata.sync_digest(share_id).unwrap(), expected);
}
