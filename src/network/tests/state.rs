use super::*;

#[test]
fn cached_manifest_tracks_local_scans_and_remote_merges() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([50; 32]);
    let endpoint = SecretKey::from_bytes(&[51; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let initial = share.manifest_snapshot().unwrap();
    assert!(Arc::ptr_eq(&initial, &share.manifest_snapshot().unwrap()));

    fs::write(root.join("local.txt"), b"local").unwrap();
    scan_and_save(&share, &share.config().unwrap()).unwrap();
    let scanned = share.manifest_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&initial, &scanned));
    assert_eq!(share.manifest_generation.load(Ordering::Relaxed), 1);
    assert!(Arc::ptr_eq(&scanned, &share.manifest_snapshot().unwrap()));

    let bytes = b"remote";
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "remote.txt".to_owned(),
            ManifestEntry {
                size: bytes.len() as u64,
                modified_at_ns: 0,
                sha256: hex::encode(Sha256::digest(bytes)),
                permissions: None,
                version: timestamp(1, SecretKey::from_bytes(&[52; 32]).public()),
            },
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    apply_remote_transfer(
        &share,
        &remote,
        &[FilePayload {
            path: "remote.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            content: URL_SAFE_NO_PAD.encode(bytes),
        }],
    )
    .unwrap();
    let merged = share.manifest_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&scanned, &merged));
    assert_eq!(share.manifest_generation.load(Ordering::Relaxed), 2);
    assert_eq!(
        merged.digest,
        share
            .paths
            .load_manifest(share_id)
            .unwrap()
            .sync_digest(share_id)
            .unwrap()
    );
    assert!(merged.manifest.entries.contains_key("local.txt"));
    assert!(merged.manifest.entries.contains_key("remote.txt"));
}

#[test]
fn failed_manifest_save_invalidates_snapshot_and_schedules_retry() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([58; 32]);
    let endpoint = SecretKey::from_bytes(&[59; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let cached = share.manifest_snapshot().unwrap();

    // A parent-directory fsync failure after rename is not injectable without a
    // production-only storage test hook. Model disk containing a replacement before
    // the attempted save fails DataPaths validation.
    let mut persisted = cached.manifest.clone();
    persisted.scanned_at_ms = 1;
    share.paths.save_manifest(&persisted).unwrap();
    let mut invalid = persisted;
    invalid.format_version = u16::MAX;
    assert!(share.save_manifest(invalid).is_err());

    assert_eq!(share.manifest_generation.load(Ordering::Relaxed), 1);
    let mut schedule = PeerSchedule::default();
    let now = Instant::now();
    schedule.after_attempt(now, 0, Some(&SyncOutcome::default()));
    assert!(!schedule.due(now, 0));
    assert!(schedule.due(now, 1));

    let recovered = share.manifest_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&cached, &recovered));
    assert_eq!(recovered.manifest.scanned_at_ms, 1);
}

#[test]
fn invalid_manifest_does_not_replace_a_valid_snapshot() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([53; 32]);
    let endpoint = SecretKey::from_bytes(&[54; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let snapshot = share.manifest_snapshot().unwrap();
    let invalid = Manifest::empty(ShareId([55; 32]), 0);
    assert!(share.save_manifest(invalid).is_err());
    assert!(Arc::ptr_eq(&snapshot, &share.manifest_snapshot().unwrap()));
    assert_eq!(share.manifest_generation.load(Ordering::Relaxed), 0);
    assert_eq!(
        share.paths.load_manifest(share_id).unwrap().share_id,
        share_id
    );
}
