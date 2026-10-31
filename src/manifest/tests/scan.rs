use super::*;

#[test]
fn scanner_preserves_versions_for_unchanged_files() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("config.txt"), "one").unwrap();
    let share_id = ShareId([1; 32]);
    let endpoint = SecretKey::from_bytes(&[2; 32]).public();
    let first = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    let second =
        scan_manifest(temporary.path(), &first.manifest, first.clock, &endpoint, 3).unwrap();
    assert_eq!(
        first.manifest.entries["config.txt"].version,
        second.manifest.entries["config.txt"].version
    );
    assert!(first.manifest_changed);
    assert!(!second.manifest_changed);
}

#[test]
fn scanner_assigns_file_versions_in_manifest_path_order() {
    let temporary = TempDir::new().unwrap();
    for path in ["z.txt", "b/a.txt", "b-1.txt", "a/z.txt", "a-1.txt"] {
        let path = temporary.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "content").unwrap();
    }
    let share_id = ShareId([26; 32]);
    let endpoint = SecretKey::from_bytes(&[27; 32]).public();
    let scanned = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    for (counter, entry) in scanned.manifest.entries.values().enumerate() {
        assert_eq!(entry.version.wall_ms, 2);
        assert_eq!(entry.version.counter, u32::try_from(counter).unwrap());
    }
}

#[test]
fn scanner_rejects_invalid_previous_state_before_reuse() {
    let temporary = TempDir::new().unwrap();
    let share_id = ShareId([30; 32]);
    let endpoint = SecretKey::from_bytes(&[31; 32]).public();
    let mut previous = Manifest::empty(share_id, 1);
    previous.format_version = u16::MAX;
    assert!(scan_manifest(temporary.path(), &previous, ClockState::new(), &endpoint, 2).is_err());
}

#[test]
fn equal_record_counts_do_not_hide_a_renamed_file() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("before"), "content").unwrap();
    let share_id = ShareId([28; 32]);
    let endpoint = SecretKey::from_bytes(&[29; 32]).public();
    let first = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    fs::rename(
        temporary.path().join("before"),
        temporary.path().join("after"),
    )
    .unwrap();
    let renamed = scan_manifest_cached_after_validation(
        temporary.path(),
        &first.manifest,
        first.clock,
        &endpoint,
        3,
    )
    .unwrap();
    assert_eq!(renamed.changes, 2);
    assert!(renamed.manifest.entries.contains_key("after"));
    assert!(renamed.manifest.tombstones.contains_key("before"));
}

#[test]
fn scanner_reports_mtime_cache_refresh_without_content_change() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("config.txt"), "one").unwrap();
    let share_id = ShareId([24; 32]);
    let endpoint = SecretKey::from_bytes(&[25; 32]).public();
    let first = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    let mut stale = first.manifest.clone();
    let stale_mtime = stale.entries["config.txt"].modified_at_ns;
    stale.entries.get_mut("config.txt").unwrap().modified_at_ns = stale_mtime.saturating_add(1);

    let refreshed = scan_manifest(temporary.path(), &stale, first.clock, &endpoint, 3).unwrap();
    assert_eq!(refreshed.changes, 0);
    assert!(refreshed.manifest_changed);
    assert_eq!(
        refreshed.manifest.entries["config.txt"].sha256,
        stale.entries["config.txt"].sha256
    );
}

#[cfg(unix)]
#[test]
fn scanner_tracks_symlink_targets_without_following_them() {
    let temporary = TempDir::new().unwrap();
    fs::write(temporary.path().join("target.txt"), "target").unwrap();
    std::os::unix::fs::symlink("target.txt", temporary.path().join("alias.txt")).unwrap();
    let share_id = ShareId([8; 32]);
    let endpoint = SecretKey::from_bytes(&[9; 32]).public();
    let scanned = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    assert_eq!(scanned.manifest.symlinks["alias.txt"].target, "target.txt");
    assert!(!scanned.manifest.entries.contains_key("alias.txt"));
}

#[cfg(unix)]
#[test]
fn scanner_tracks_file_and_directory_permissions() {
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join("private");
    let empty_directory = temporary.path().join("empty");
    let file = directory.join("config.txt");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(&empty_directory).unwrap();
    fs::write(&file, "one").unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(&empty_directory, fs::Permissions::from_mode(0o710)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let share_id = ShareId([4; 32]);
    let endpoint = SecretKey::from_bytes(&[5; 32]).public();
    let first = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    assert_eq!(
        first.manifest.entries["private/config.txt"].permissions,
        Some(0o640)
    );
    assert_eq!(
        first.manifest.directories["private"].permissions,
        Some(0o750)
    );
    assert_eq!(first.manifest.directories["empty"].permissions, Some(0o710));

    let unchanged = scan_manifest(
        temporary.path(),
        &first.manifest,
        first.clock.clone(),
        &endpoint,
        3,
    )
    .unwrap();
    assert_eq!(
        unchanged.manifest.entries["private/config.txt"].version,
        first.manifest.entries["private/config.txt"].version
    );
    assert_eq!(
        unchanged.manifest.directories["private"].version,
        first.manifest.directories["private"].version
    );

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let changed = scan_manifest(
        temporary.path(),
        &unchanged.manifest,
        unchanged.clock,
        &endpoint,
        4,
    )
    .unwrap();
    assert_eq!(
        changed.manifest.entries["private/config.txt"].permissions,
        Some(0o600)
    );
    assert_eq!(
        changed.manifest.directories["private"].permissions,
        Some(0o700)
    );
    assert_ne!(
        changed.manifest.entries["private/config.txt"].version,
        unchanged.manifest.entries["private/config.txt"].version
    );
    assert_ne!(
        changed.manifest.directories["private"].version,
        unchanged.manifest.directories["private"].version
    );
}

#[cfg(unix)]
#[test]
fn scanner_preserves_unknown_permissions_from_windows() {
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join("private");
    let file = directory.join("config.txt");
    fs::create_dir(&directory).unwrap();
    fs::write(&file, "one").unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let share_id = ShareId([10; 32]);
    let endpoint = SecretKey::from_bytes(&[11; 32]).public();
    let first = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    let mut windows = first.manifest.clone();
    windows
        .entries
        .get_mut("private/config.txt")
        .unwrap()
        .permissions = None;
    windows.directories.get_mut("private").unwrap().permissions = None;

    let rescanned = scan_manifest(temporary.path(), &windows, first.clock, &endpoint, 3).unwrap();
    assert_eq!(rescanned.changes, 0);
    assert_eq!(
        rescanned.manifest.entries["private/config.txt"].version,
        windows.entries["private/config.txt"].version
    );
    assert_eq!(
        rescanned.manifest.directories["private"].version,
        windows.directories["private"].version
    );
    assert_eq!(
        rescanned.manifest.entries["private/config.txt"].permissions,
        None
    );
    assert_eq!(rescanned.manifest.directories["private"].permissions, None);

    let fast_path = scan_manifest(
        temporary.path(),
        &rescanned.manifest,
        rescanned.clock,
        &endpoint,
        4,
    )
    .unwrap();
    assert_eq!(fast_path.changes, 0);
    assert_eq!(
        fast_path.manifest.entries["private/config.txt"].version,
        rescanned.manifest.entries["private/config.txt"].version
    );
    assert_eq!(
        fast_path.manifest.directories["private"].version,
        rescanned.manifest.directories["private"].version
    );
}

#[cfg(unix)]
#[test]
fn legacy_manifests_gain_permissions_on_the_next_scan() {
    let temporary = TempDir::new().unwrap();
    let file = temporary.path().join("config.txt");
    fs::write(&file, "one").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let share_id = ShareId([6; 32]);
    let endpoint = SecretKey::from_bytes(&[7; 32]).public();
    let scanned = scan_manifest(
        temporary.path(),
        &Manifest::empty(share_id, 1),
        ClockState::new(),
        &endpoint,
        2,
    )
    .unwrap();
    let mut legacy = serde_json::to_value(&scanned.manifest).unwrap();
    legacy["format_version"] = serde_json::json!(LEGACY_MANIFEST_FORMAT_VERSION);
    legacy["directories"] = serde_json::json!({});
    legacy["entries"]["config.txt"]
        .as_object_mut()
        .unwrap()
        .remove("permissions");
    let legacy: Manifest = serde_json::from_value(legacy).unwrap();
    legacy.validate(share_id).unwrap();

    let migrated = scan_manifest(temporary.path(), &legacy, scanned.clock, &endpoint, 3).unwrap();
    assert_eq!(migrated.manifest.format_version, MANIFEST_FORMAT_VERSION);
    assert_eq!(
        migrated.manifest.entries["config.txt"].permissions,
        Some(0o640)
    );
    assert_ne!(
        migrated.manifest.entries["config.txt"].version,
        legacy.entries["config.txt"].version
    );
}
