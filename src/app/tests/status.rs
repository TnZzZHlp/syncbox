use super::*;

#[test]
fn stale_runtime_status_is_reported_as_stopped() {
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join("workspace");
    fs::create_dir_all(&directory).unwrap();
    let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
    let result = app.init(&directory, None).unwrap();
    let _lock = app.paths().acquire_share_lock(result.share_id).unwrap();
    let mut runtime = RuntimeStatus::stopped(0);
    runtime.process_id = std::process::id();
    runtime.state = RuntimeState::Running;
    runtime.heartbeat_at_ms = 0;
    app.paths()
        .save_runtime_status(result.share_id, &runtime)
        .unwrap();
    let report = app.status(Some(&result.share_id.to_string())).unwrap();
    assert_eq!(report.shares[0].runtime, "stopped");
}
