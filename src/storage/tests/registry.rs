use super::*;

#[test]
fn invalid_share_directories_are_not_registered_shares() {
    let temporary = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temporary.path().join("data"));
    paths.ensure_layout().unwrap();
    fs::create_dir(paths.shares_dir().join("not-a-share")).unwrap();
    assert_eq!(
        paths.list_share_ids().unwrap(),
        Vec::<crate::types::ShareId>::new()
    );
}

#[test]
fn removing_share_state_preserves_other_directories() {
    let temporary = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temporary.path().join("data"));
    let share_id = ShareId::random();
    let other_share_id = ShareId::random();
    let shared_directory = temporary.path().join("shared");
    fs::create_dir(&shared_directory).unwrap();
    fs::write(shared_directory.join("keep.txt"), "keep").unwrap();
    paths.ensure_share_layout(share_id).unwrap();
    paths.ensure_share_layout(other_share_id).unwrap();
    fs::write(paths.share_config(share_id), "private state").unwrap();

    paths.remove_share_state(share_id).unwrap();

    assert!(!paths.share_dir(share_id).exists());
    assert!(paths.share_dir(other_share_id).is_dir());
    assert_eq!(
        fs::read_to_string(shared_directory.join("keep.txt")).unwrap(),
        "keep"
    );
    assert_eq!(paths.list_share_ids().unwrap(), vec![other_share_id]);
}

#[cfg(unix)]
#[test]
fn removing_share_state_rejects_a_symlink() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temporary.path().join("data"));
    let share_id = ShareId::random();
    let outside = temporary.path().join("outside");
    paths.ensure_layout().unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.txt"), "keep").unwrap();
    symlink(&outside, paths.share_dir(share_id)).unwrap();

    let error = paths.remove_share_state(share_id).unwrap_err().to_string();

    assert!(error.contains("is not a directory"));
    assert_eq!(
        fs::read_to_string(outside.join("keep.txt")).unwrap(),
        "keep"
    );
}

#[cfg(unix)]
#[test]
fn removing_share_state_rejects_a_symlinked_shares_parent() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().unwrap();
    let data_root = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    let paths = DataPaths::from_root(data_root.clone());
    let share_id = ShareId::random();
    fs::create_dir_all(&data_root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::create_dir(outside.join(share_id.to_string())).unwrap();
    fs::write(outside.join(share_id.to_string()).join("keep.txt"), "keep").unwrap();
    symlink(&outside, data_root.join("shares")).unwrap();

    let error = paths.remove_share_state(share_id).unwrap_err().to_string();

    assert!(error.contains("registered shares path"));
    assert!(outside.join(share_id.to_string()).is_dir());
    assert_eq!(
        fs::read_to_string(outside.join(share_id.to_string()).join("keep.txt")).unwrap(),
        "keep"
    );
}
