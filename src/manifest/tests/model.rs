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
fn sync_digest_keeps_the_existing_timestamp_encoding() {
    let share_id = ShareId([95; 32]);
    let author = *SecretKey::from_bytes(&[96; 32]).public().as_bytes();
    let mut manifest = Manifest::empty(share_id, 1);
    for index in 0_u64..8 {
        let version = HlcTimestamp {
            wall_ms: 123_456_789 + index,
            counter: u32::try_from(index).unwrap(),
            author,
        };
        match index % 4 {
            0 => {
                manifest.entries.insert(
                    format!("file-{index:05}"),
                    ManifestEntry {
                        size: index,
                        modified_at_ns: 0,
                        sha256: blake3::hash(&index.to_le_bytes()).to_hex().to_string(),
                        permissions: if index % 8 < 4 { None } else { Some(0o640) },
                        version,
                    },
                );
            }
            1 => {
                manifest.directories.insert(
                    format!("dir-{index:05}"),
                    DirectoryEntry {
                        permissions: if index % 8 < 4 { Some(0o750) } else { None },
                        version,
                    },
                );
            }
            2 => {
                manifest.symlinks.insert(
                    format!("link-{index:05}"),
                    SymlinkEntry {
                        target: "file-00000".to_owned(),
                        version,
                    },
                );
            }
            _ => {
                manifest
                    .tombstones
                    .insert(format!("gone-{index:05}"), Tombstone { version });
            }
        }
    }
    assert_eq!(
        hex::encode(manifest.sync_digest(share_id).unwrap()),
        "c0436ce07c0a01a8f5cb58b18431745728e9aaf91b22a40f3bb9cbafce1d6622"
    );
}

#[test]
fn shared_ancestor_validation_still_rejects_new_blocking_prefixes() {
    let share_id = ShareId([99; 32]);
    let version = HlcTimestamp {
        wall_ms: 1,
        counter: 0,
        author: *SecretKey::from_bytes(&[100; 32]).public().as_bytes(),
    };
    let file = ManifestEntry {
        size: 1,
        modified_at_ns: 0,
        sha256: "a".repeat(64),
        permissions: None,
        version,
    };
    for blocker in ["root/a", "root/ab", "root/é"] {
        for kind in 0..3 {
            let mut manifest = Manifest::empty(share_id, 1);
            manifest.entries.insert("root/0".to_owned(), file.clone());
            manifest
                .entries
                .insert(format!("{blocker}/child"), file.clone());
            manifest.directories.insert(
                "root/z/dir".to_owned(),
                DirectoryEntry {
                    permissions: None,
                    version,
                },
            );
            manifest.validate(share_id).unwrap();
            match kind {
                0 => {
                    manifest.entries.insert(blocker.to_owned(), file.clone());
                }
                1 => {
                    manifest.symlinks.insert(
                        blocker.to_owned(),
                        SymlinkEntry {
                            target: "target".to_owned(),
                            version,
                        },
                    );
                }
                _ => {
                    manifest
                        .tombstones
                        .insert(blocker.to_owned(), Tombstone { version });
                }
            }
            assert!(manifest.validate(share_id).is_err());
        }
    }
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
