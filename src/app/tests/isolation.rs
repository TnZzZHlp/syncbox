use super::*;

#[test]
fn same_directory_cannot_be_registered_twice() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    app.init(&root, None).unwrap();
    let error = app.init(&root, None).unwrap_err();
    assert!(error.to_string().contains("already registered"));
}

#[test]
fn nested_directories_cannot_be_registered_as_separate_shares() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    let nested = root.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    app.init(&root, None).unwrap();
    let error = app.init(&nested, None).unwrap_err();
    assert!(error.to_string().contains("already registered"));
}

#[test]
fn application_data_directory_cannot_be_a_share() {
    let temporary = TempDir::new().unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let data_root = app.paths().root().to_path_buf();
    let error = app.init(&data_root, None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("overlaps the Syncbox application data directory")
    );
    assert!(!app.paths().identity_dir().exists());
    assert!(!app.paths().shares_dir().exists());
}

#[test]
fn data_directory_inside_a_share_is_rejected_before_state_is_created() {
    let temporary = TempDir::new().unwrap();
    let shared_directory = temporary.path().join("workspace");
    fs::create_dir_all(&shared_directory).unwrap();
    let app = App::with_paths(DataPaths::from_root(shared_directory.join("state")));
    let error = app.init(&shared_directory, None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("overlaps the Syncbox application data directory")
    );
    assert!(!shared_directory.join("state/identity").exists());
    assert!(!shared_directory.join("state/shares").exists());
}
