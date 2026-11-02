use super::*;

#[cfg(windows)]
#[test]
fn windows_retains_remote_symlink_as_unsupported_without_blocking_files() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([43; 32]);
    let local_endpoint = SecretKey::from_bytes(&[44; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[45; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), local_endpoint);
    let bytes = b"content";
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "file.txt".to_owned(),
            ManifestEntry {
                size: bytes.len() as u64,
                modified_at_ns: 0,
                sha256: hex::encode(Sha256::digest(bytes)),
                permissions: None,
                version: timestamp(1, remote_endpoint),
            },
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::from([(
            "alias.txt".to_owned(),
            SymlinkEntry {
                target: "file.txt".to_owned(),
                version: timestamp(2, remote_endpoint),
            },
        )]),
        tombstones: BTreeMap::new(),
    };
    let files = vec![FilePayload {
        path: "file.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        content: URL_SAFE_NO_PAD.encode(bytes),
    }];

    let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();

    assert_eq!(outcome.pending_downloads, 0);
    assert_eq!(outcome.unsupported_items, 1);
    assert_eq!(fs::read(root.join("file.txt")).unwrap(), bytes);
    assert!(!root.join("alias.txt").exists());
    let stored = share.paths.load_manifest(share_id).unwrap();
    assert_eq!(stored.symlinks, remote.symlinks);
    let scanned = crate::manifest::scan_manifest(
        &root,
        &stored,
        share.paths.load_clock(share_id).unwrap(),
        &local_endpoint,
        3,
    )
    .unwrap();
    assert_eq!(scanned.changes, 0);
    assert_eq!(scanned.manifest.symlinks, remote.symlinks);
}

#[tokio::test]
async fn binary_file_transfer_resumes_and_verifies_staged_files() {
    let source_dir = TempDir::new().unwrap();
    let destination_dir = TempDir::new().unwrap();
    let source_root = source_dir.path().join("share");
    let destination_root = destination_dir.path().join("share");
    fs::create_dir(&source_root).unwrap();
    fs::create_dir(&destination_root).unwrap();
    let share_id = ShareId([61; 32]);
    let sender_id = SecretKey::from_bytes(&[62; 32]).public();
    let receiver_id = SecretKey::from_bytes(&[63; 32]).public();
    let source = active_share(&source_root, Manifest::empty(share_id, 0), sender_id);
    let destination = active_share(&destination_root, Manifest::empty(share_id, 0), receiver_id);
    let payload = vec![0xa5; MAX_CHUNK_BYTES + 1000];
    let contents = [
        ("large", payload.as_slice()),
        ("empty", b""),
        ("resumed", b"resume"),
        ("last", b"last"),
    ];
    let files = contents
        .iter()
        .map(|(name, bytes)| {
            fs::write(source_root.join(name), bytes).unwrap();
            TransferFile {
                path: (*name).to_owned(),
                sha256: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                offset: match *name {
                    "large" => 73,
                    "resumed" => bytes.len() as u64,
                    _ => 0,
                },
            }
        })
        .collect::<Vec<_>>();
    let partial = partial_path(&destination, &files[0].path, &files[0].sha256);
    fs::write(&partial, &payload[..73]).unwrap();
    fs::write(
        partial_path(&destination, &files[2].path, &files[2].sha256),
        b"resume",
    )
    .unwrap();
    let (mut send, mut recv) = tokio::io::duplex(4096);
    let (sent, received) = tokio::join!(
        send_file_chunks_from_root(&source, receiver_id, &files, &mut send),
        receive_file_chunks(&destination, sender_id, &files, &mut recv),
    );
    sent.unwrap();
    let completed = received.unwrap();
    assert_eq!(completed.len(), contents.len());
    for (file, (_, bytes)) in completed.iter().zip(contents) {
        assert_eq!(fs::read(&file.staged_path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn valid_transfer_partial_resumes_and_survives_verification() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([30; 32]);
    let endpoint = SecretKey::from_bytes(&[31; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let bytes = b"valid data";
    let file = TransferFile {
        path: "file.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        offset: 0,
    };
    let partial = partial_path(&share, &file.path, &file.sha256);
    fs::write(&partial, &bytes[..5]).unwrap();

    assert_eq!(
        partial_size(&share, &file.path, &file.sha256, file.size).unwrap(),
        5
    );
    fs::write(&partial, bytes).unwrap();
    verify_partial(&partial, &file, &mut Vec::new()).unwrap();
    assert!(partial.exists());
}

#[cfg(unix)]
#[test]
fn invalid_transfer_partial_is_removed_after_hash_mismatch() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([32; 32]);
    let endpoint = SecretKey::from_bytes(&[33; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let bytes = b"valid data";
    let file = TransferFile {
        path: "file.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        offset: 0,
    };
    let partial = partial_path(&share, &file.path, &file.sha256);
    fs::write(&partial, b"corrupt!!!").unwrap();

    let error = verify_partial(&partial, &file, &mut Vec::new()).unwrap_err();

    assert!(format!("{error:#}").contains("file.txt"));
    assert!(!partial.exists());
    assert_eq!(
        partial_size(&share, &file.path, &file.sha256, file.size).unwrap(),
        0
    );
}

#[cfg(unix)]
#[test]
fn rejected_parent_symlink_restores_prepared_directory_permissions() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    let directory = root.join("directory");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, directory.join("link")).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
    let error = with_writable_parents::<()>(&root, "directory/link/file", true, || {
        panic!("an unsafe parent must prevent the operation")
    })
    .unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
        0o555
    );
    assert!(!outside.join("file").exists());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn readable_file_permissions_are_restored_after_an_operation_error() {
    let temporary = TempDir::new().unwrap();
    let target = temporary.path().join("file");
    fs::write(&target, b"content").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).unwrap();
    let metadata = fs::symlink_metadata(&target).unwrap();
    let result = with_readable_file::<()>(&target, &metadata, || Err(anyhow!("operation failed")));
    assert_eq!(result.unwrap_err().to_string(), "operation failed");
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0
    );
}

#[cfg(unix)]
#[test]
fn cross_device_copy_temporarily_makes_read_only_target_writable() {
    let temporary = TempDir::new().unwrap();
    let target = temporary.path().join("target.txt");
    let staged = temporary.path().join("staged.part");
    fs::write(&target, b"old").unwrap();
    fs::write(&staged, b"new").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();

    with_writable_cross_device_target(&target, None, || {
        fs::copy(&staged, &target)
            .map(|_| ())
            .context("simulated cross-device copy failed")
    })
    .unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(mode(&target), 0o444);
    assert!(staged.exists());
}

#[cfg(unix)]
#[test]
fn cross_device_copy_restores_permissions_after_failure() {
    let temporary = TempDir::new().unwrap();
    let target = temporary.path().join("target.txt");
    let staged = temporary.path().join("staged.part");
    fs::write(&target, b"old").unwrap();
    fs::write(&staged, b"new").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();

    let error = with_writable_cross_device_target(&target, None, || {
        Err::<(), _>(anyhow!("simulated cross-device copy failure"))
    })
    .unwrap_err();

    assert!(format!("{error:#}").contains("simulated cross-device copy failure"));
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(mode(&target), 0o444);
    assert!(staged.exists());
}

#[cfg(unix)]
#[test]
fn remote_transfer_applies_file_and_directory_permissions() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([10; 32]);
    let local_endpoint = SecretKey::from_bytes(&[11; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[12; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), local_endpoint);
    let bytes = b"secret";
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::from([(
            "private/config.txt".to_owned(),
            file_entry(bytes, 0o640, timestamp(2, remote_endpoint)),
        )]),
        directories: BTreeMap::from([
            (
                "empty".to_owned(),
                directory_entry(0o710, timestamp(1, remote_endpoint)),
            ),
            (
                "private".to_owned(),
                directory_entry(0o750, timestamp(1, remote_endpoint)),
            ),
        ]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let files = vec![FilePayload {
        path: "private/config.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        content: URL_SAFE_NO_PAD.encode(bytes),
    }];

    let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();
    assert_eq!(outcome.pending_downloads, 0);
    assert_eq!(fs::read(root.join("private/config.txt")).unwrap(), bytes);
    assert_eq!(mode(&root.join("private/config.txt")), 0o640);
    assert_eq!(mode(&root.join("private")), 0o750);
    assert_eq!(mode(&root.join("empty")), 0o710);
    let stored = share.paths.load_manifest(share_id).unwrap();
    assert_eq!(stored.entries, remote.entries);
    assert_eq!(stored.directories, remote.directories);
}

#[cfg(unix)]
#[test]
fn metadata_only_permission_updates_do_not_need_file_payloads() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    let directory = root.join("private");
    let file = directory.join("config.txt");
    fs::create_dir_all(&directory).unwrap();
    let bytes = b"same content";
    fs::write(&file, bytes).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    let share_id = ShareId([13; 32]);
    let local_endpoint = SecretKey::from_bytes(&[14; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[15; 32]).public();
    let local = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "private/config.txt".to_owned(),
            file_entry(bytes, 0o000, timestamp(1, local_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "private".to_owned(),
            directory_entry(0o755, timestamp(1, local_endpoint)),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let share = active_share(&root, local.clone(), local_endpoint);
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::from([(
            "private/config.txt".to_owned(),
            file_entry(bytes, 0o600, timestamp(2, remote_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "private".to_owned(),
            directory_entry(0o700, timestamp(2, remote_endpoint)),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let (transfer, pending_updates) = make_transfer_request(&share, &local, &remote).unwrap();
    assert_eq!(pending_updates, 0);
    assert_eq!(transfer.download_paths, Vec::<String>::new());
    assert!(transfer.uploads.is_empty());

    let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
    assert_eq!(outcome.pending_downloads, 0);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&directory), 0o700);
    let stored = share.paths.load_manifest(share_id).unwrap();
    assert_eq!(stored.entries, remote.entries);
    assert_eq!(stored.directories, remote.directories);
}

#[cfg(unix)]
#[test]
fn remote_transfer_applies_symlink_target_without_following_it() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([20; 32]);
    let local_endpoint = SecretKey::from_bytes(&[21; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[22; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), local_endpoint);
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::new(),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::from([(
            "alias.txt".to_owned(),
            SymlinkEntry {
                target: "target.txt".to_owned(),
                version: timestamp(2, remote_endpoint),
            },
        )]),
        tombstones: BTreeMap::new(),
    };

    let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
    assert_eq!(outcome.pending_downloads, 0);
    assert_eq!(
        fs::read_link(root.join("alias.txt")).unwrap(),
        Path::new("target.txt")
    );
    assert_eq!(
        share.paths.load_manifest(share_id).unwrap().symlinks,
        remote.symlinks
    );
}

#[cfg(unix)]
#[test]
fn file_updates_work_inside_a_previously_read_only_directory() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    let directory = root.join("private");
    let file = directory.join("config.txt");
    fs::create_dir_all(&directory).unwrap();
    let old_bytes = b"old";
    let new_bytes = b"new";
    fs::write(&file, old_bytes).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
    let share_id = ShareId([16; 32]);
    let local_endpoint = SecretKey::from_bytes(&[17; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[18; 32]).public();
    let directory_version = timestamp(1, remote_endpoint);
    let local = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "private/config.txt".to_owned(),
            file_entry(old_bytes, 0o444, timestamp(1, local_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "private".to_owned(),
            directory_entry(0o555, directory_version),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let share = active_share(&root, local, local_endpoint);
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::from([(
            "private/config.txt".to_owned(),
            file_entry(new_bytes, 0o600, timestamp(2, remote_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "private".to_owned(),
            directory_entry(0o555, directory_version),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let files = vec![FilePayload {
        path: "private/config.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(new_bytes)),
        content: URL_SAFE_NO_PAD.encode(new_bytes),
    }];

    let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();
    assert_eq!(outcome.pending_downloads, 0);
    assert_eq!(fs::read(&file).unwrap(), new_bytes);
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&directory), 0o555);
}

#[cfg(unix)]
#[test]
fn remote_transfer_replaces_a_file_with_a_directory() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let path = root.join("entry");
    fs::write(&path, "old file").unwrap();
    let share_id = ShareId([19; 32]);
    let local_endpoint = SecretKey::from_bytes(&[20; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[21; 32]).public();
    let local = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "entry".to_owned(),
            file_entry(b"old file", 0o600, timestamp(1, local_endpoint)),
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let share = active_share(&root, local, local_endpoint);
    let bytes = b"nested file";
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::from([(
            "entry/config.txt".to_owned(),
            file_entry(bytes, 0o640, timestamp(3, remote_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "entry".to_owned(),
            directory_entry(0o750, timestamp(2, remote_endpoint)),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let files = vec![FilePayload {
        path: "entry/config.txt".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        content: URL_SAFE_NO_PAD.encode(bytes),
    }];

    let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();

    assert_eq!(outcome.pending_downloads, 0);
    assert!(path.is_dir());
    assert_eq!(fs::read(path.join("config.txt")).unwrap(), bytes);
    assert_eq!(mode(&path), 0o750);
    assert_eq!(mode(&path.join("config.txt")), 0o640);
    let stored = share.paths.load_manifest(share_id).unwrap();
    assert_eq!(stored.entries, remote.entries);
    assert_eq!(stored.directories, remote.directories);
}

#[cfg(unix)]
#[test]
fn remote_transfer_replaces_an_empty_directory_with_a_file() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    let directory = root.join("entry");
    let nested_file = directory.join("old.txt");
    fs::create_dir_all(&directory).unwrap();
    fs::write(&nested_file, "old nested file").unwrap();
    let share_id = ShareId([22; 32]);
    let local_endpoint = SecretKey::from_bytes(&[23; 32]).public();
    let remote_endpoint = SecretKey::from_bytes(&[24; 32]).public();
    let local = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "entry/old.txt".to_owned(),
            file_entry(b"old nested file", 0o600, timestamp(1, local_endpoint)),
        )]),
        directories: BTreeMap::from([(
            "entry".to_owned(),
            directory_entry(0o700, timestamp(1, local_endpoint)),
        )]),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let share = active_share(&root, local, local_endpoint);
    let bytes = b"replacement file";
    let remote = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 2,
        entries: BTreeMap::from([(
            "entry".to_owned(),
            file_entry(bytes, 0o640, timestamp(3, remote_endpoint)),
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::from([(
            "entry/old.txt".to_owned(),
            Tombstone {
                version: timestamp(2, remote_endpoint),
            },
        )]),
    };
    let files = vec![FilePayload {
        path: "entry".to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        content: URL_SAFE_NO_PAD.encode(bytes),
    }];

    let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();

    assert_eq!(outcome.pending_downloads, 0);
    assert!(directory.is_file());
    assert_eq!(fs::read(&directory).unwrap(), bytes);
    assert_eq!(mode(&directory), 0o640);
    let stored = share.paths.load_manifest(share_id).unwrap();
    assert_eq!(stored.entries, remote.entries);
    assert_eq!(stored.directories, remote.directories);
    assert!(stored.tombstones == remote.tombstones);
}

#[test]
fn remote_transfer_removes_nested_records_before_their_directories() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir_all(root.join("tree/sub")).unwrap();
    fs::write(root.join("tree/sub/file"), b"content").unwrap();
    let share_id = ShareId([93; 32]);
    let endpoint = SecretKey::from_bytes(&[94; 32]).public();
    let mut local = Manifest::empty(share_id, 1);
    local.entries.insert(
        "tree/sub/file".to_owned(),
        ManifestEntry {
            size: 7,
            modified_at_ns: 0,
            sha256: hex::encode(Sha256::digest(b"content")),
            permissions: None,
            version: timestamp(1, endpoint),
        },
    );
    for path in ["tree", "tree/sub"] {
        local.directories.insert(
            path.to_owned(),
            crate::manifest::DirectoryEntry {
                permissions: None,
                version: timestamp(1, endpoint),
            },
        );
    }
    let share = active_share(&root, local, endpoint);
    let mut remote = Manifest::empty(share_id, 2);
    for path in ["tree", "tree/sub", "tree/sub/file"] {
        remote.tombstones.insert(
            path.to_owned(),
            crate::manifest::Tombstone {
                version: timestamp(2, endpoint),
            },
        );
    }
    let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
    assert_eq!(outcome.applied_records, 3);
    assert!(!root.join("tree").exists());
    assert!(share.paths.load_manifest(share_id).unwrap().tombstones == remote.tombstones);
}

#[cfg(unix)]
#[test]
fn removing_a_missing_nested_path_does_not_create_parent_directories() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();

    remove_local_path(&root, "missing/config.txt").unwrap();

    assert!(!root.join("missing").exists());
}

#[test]
fn unfiltered_pkarr_candidates_keep_direct_addresses() {
    let data = EndpointData::from_iter([
        TransportAddr::Ip("192.0.2.1:443".parse().unwrap()),
        TransportAddr::Relay("https://relay.example.com".parse().unwrap()),
    ]);
    assert_eq!(
        data.apply_filter(&AddrFilter::unfiltered()).addrs().count(),
        2
    );
}
