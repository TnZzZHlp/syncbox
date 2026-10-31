use super::*;

#[test]
fn resized_partial_preserves_prefix_and_returns_a_zero_positioned_handle() {
    use std::io::Read as _;

    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("partial");
    fs::write(&path, b"prefix-tail").unwrap();
    let mut file = ensure_partial_file(&path, 6).unwrap();
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"prefix");
}

#[test]
fn chunk_ranges_resume_from_existing_offset() {
    assert_eq!(chunk_ranges(10, 4, 3), vec![(4, 3), (7, 3), (10, 0)]);
}

#[test]
fn download_resume_checks_are_limited_to_the_selected_batch() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([64; 32]);
    let endpoint = SecretKey::from_bytes(&[65; 32]).public();
    let mut local = Manifest::empty(share_id, 1);
    let share = active_share(&root, local.clone(), endpoint);
    let mut remote = Manifest::empty(share_id, 2);
    for index in 0..=MAX_TRANSFER_FILES {
        remote.entries.insert(
            format!("file-{index:03}"),
            ManifestEntry {
                size: 1,
                modified_at_ns: 0,
                sha256: "a".repeat(64),
                permissions: None,
                version: timestamp(2, endpoint),
            },
        );
    }
    let (deferred_path, deferred) = remote.entries.last_key_value().unwrap();
    fs::create_dir(partial_path(&share, deferred_path, &deferred.sha256)).unwrap();
    let (request, _) = make_transfer_request(&share, &local, &remote).unwrap();
    assert_eq!(request.download_paths.len(), MAX_TRANSFER_FILES);
    assert_eq!(request.download_paths.first().unwrap(), "file-000");
    assert_eq!(request.download_paths.last().unwrap(), "file-255");
    for path in request.download_paths {
        local
            .entries
            .insert(path.clone(), remote.entries[&path].clone());
    }
    let error = make_transfer_request(&share, &local, &remote)
        .err()
        .unwrap();
    assert!(error.to_string().contains("not a regular file"));
}

#[test]
fn capped_uploads_keep_the_remaining_update_count() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([66; 32]);
    let endpoint = SecretKey::from_bytes(&[67; 32]).public();
    let mut local = Manifest::empty(share_id, 1);
    let remote = Manifest::empty(share_id, 2);
    let share = active_share(&root, local.clone(), endpoint);
    for index in 0..=MAX_TRANSFER_FILES {
        local.entries.insert(
            format!("file-{index:03}"),
            ManifestEntry {
                size: 1,
                modified_at_ns: 0,
                sha256: "a".repeat(64),
                permissions: None,
                version: timestamp(2, endpoint),
            },
        );
    }
    let (request, pending) = make_transfer_request(&share, &local, &remote).unwrap();
    assert_eq!(request.uploads.len(), MAX_TRANSFER_FILES);
    assert_eq!(pending, 1);
}

#[test]
fn stale_remote_files_are_not_counted_as_pending_downloads() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("newer"), b"keep").unwrap();
    let share_id = ShareId([68; 32]);
    let endpoint = SecretKey::from_bytes(&[69; 32]).public();
    let mut local = Manifest::empty(share_id, 1);
    local.entries.insert(
        "newer".to_owned(),
        ManifestEntry {
            size: 4,
            modified_at_ns: 0,
            sha256: hex::encode(Sha256::digest(b"keep")),
            permissions: None,
            version: timestamp(3, endpoint),
        },
    );
    let share = active_share(&root, local.clone(), endpoint);
    let mut remote = local.clone();
    remote.entries.get_mut("newer").unwrap().version = timestamp(2, endpoint);
    remote.entries.insert(
        "missing".to_owned(),
        ManifestEntry {
            size: 1,
            modified_at_ns: 0,
            sha256: hex::encode(Sha256::digest(b"x")),
            permissions: None,
            version: timestamp(4, endpoint),
        },
    );
    let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
    assert_eq!(outcome.pending_downloads, 1);
    assert_eq!(
        share.paths.load_manifest(share_id).unwrap().entries,
        local.entries
    );
    assert_eq!(fs::read(root.join("newer")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn transfer_descriptors_accept_files_larger_than_sixteen_mib() {
    let bytes = vec![7_u8; 17 * 1024 * 1024];
    let share_id = ShareId([23; 32]);
    let endpoint = SecretKey::from_bytes(&[24; 32]).public();
    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "large.bin".to_owned(),
            file_entry(&bytes, 0o640, timestamp(1, endpoint)),
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let file = TransferFile {
        path: "large.bin".to_owned(),
        sha256: manifest.entries["large.bin"].sha256.clone(),
        size: bytes.len() as u64,
        offset: 0,
    };
    validate_transfer_files(&[file], &manifest).unwrap();
}

#[cfg(unix)]
#[test]
fn transfer_request_reuses_authenticated_manifest() {
    let share_id = ShareId([40; 32]);
    let endpoint = SecretKey::from_bytes(&[41; 32]).public();
    let bytes = b"payload";
    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        share_id,
        scanned_at_ms: 1,
        entries: BTreeMap::from([(
            "file.txt".to_owned(),
            file_entry(bytes, 0o640, timestamp(1, endpoint)),
        )]),
        directories: BTreeMap::new(),
        symlinks: BTreeMap::new(),
        tombstones: BTreeMap::new(),
    };
    let request = TransferRequest {
        protocol_version: PROTOCOL_VERSION,
        share_id,
        download_paths: Vec::new(),
        download_resumes: Vec::new(),
        uploads: vec![TransferFile {
            path: "file.txt".to_owned(),
            sha256: manifest.entries["file.txt"].sha256.clone(),
            size: bytes.len() as u64,
            offset: 0,
        }],
    };
    let encoded = serde_json::to_value(&request).unwrap();

    assert!(encoded.get("manifest").is_none());
    validate_transfer_request(&request, share_id, &manifest).unwrap();
    assert!(validate_transfer_request(&request, share_id, &Manifest::empty(share_id, 2)).is_err());
}
