use super::*;

#[test]
fn init_registers_state_outside_the_shared_directory() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("settings.txt"), "value").unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&root, Some("config")).unwrap();
    assert!(!root.join(".syncbox").exists());
    assert!(app.paths().share_config(result.share_id).exists());
    assert!(app.paths().share_manifest(result.share_id).exists());
    assert!(app.paths().share_clock(result.share_id).exists());
    assert!(app.paths().share_known_peers(result.share_id).exists());
    assert!(app.paths().share_runtime_status(result.share_id).exists());
}

#[test]
fn remove_unregisters_share_without_deleting_local_files() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("keep.txt"), "keep").unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&root, None).unwrap();
    let share_id = result.share_id.to_string();

    let removed = app.remove(&share_id[..8]).unwrap();

    assert_eq!(removed.share_id, result.share_id);
    assert!(!app.paths().share_dir(result.share_id).exists());
    assert_eq!(fs::read_to_string(root.join("keep.txt")).unwrap(), "keep");
    assert_eq!(app.all_share_ids().unwrap(), Vec::<ShareId>::new());
}

#[test]
fn remove_requires_full_id_for_invalid_state() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&root, None).unwrap();
    let share_id = result.share_id.to_string();
    fs::write(app.paths().share_manifest(result.share_id), "invalid").unwrap();

    let error = app.remove(&share_id[..8]).unwrap_err().to_string();
    assert!(error.contains("use its full 64-character Share ID"));
    assert!(app.paths().share_dir(result.share_id).is_dir());

    app.remove(&share_id).unwrap();
    assert!(!app.paths().share_dir(result.share_id).exists());
    assert!(root.is_dir());
}

#[test]
fn remove_rejects_a_share_that_is_in_use() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&root, None).unwrap();
    let _lock = app.paths().acquire_share_lock(result.share_id).unwrap();

    let error = app.remove(&result.share_id.to_string()).unwrap_err();

    assert!(error.to_string().contains("currently in use"));
    assert!(app.paths().share_dir(result.share_id).is_dir());
}

#[test]
fn multiple_shares_use_one_device_identity_and_independent_state() {
    let temporary = TempDir::new().unwrap();
    let first_directory = temporary.path().join("first");
    let second_directory = temporary.path().join("second");
    fs::create_dir_all(&first_directory).unwrap();
    fs::create_dir_all(&second_directory).unwrap();
    fs::write(first_directory.join("one.txt"), "one").unwrap();
    fs::write(second_directory.join("two.txt"), "two").unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let first = app.init(&first_directory, Some("first")).unwrap();
    let second = app.init(&second_directory, Some("second")).unwrap();
    assert_ne!(first.share_id, second.share_id);
    assert_eq!(first.endpoint_id, second.endpoint_id);
    let report = app.status(None).unwrap();
    assert_eq!(report.shares.len(), 2);
    assert!(app.paths().share_manifest(first.share_id).exists());
    assert!(app.paths().share_manifest(second.share_id).exists());
}
