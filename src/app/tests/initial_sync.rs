use super::*;

#[tokio::test(flavor = "current_thread")]
async fn initial_sync_propagates_removed_share_state_errors() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&root, None).unwrap();
    let identity = identity::load_or_create(app.paths()).unwrap();
    app.paths().remove_share_state(result.share_id).unwrap();

    let error = network::attempt_initial_sync(app.paths().clone(), identity, result.share_id)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("unable to inspect"));
}
