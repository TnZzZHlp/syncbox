use super::*;

#[test]
fn state_file_replacement_keeps_the_latest_complete_value() {
    let temporary = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temporary.path().join("data"));
    paths.ensure_layout().unwrap();
    let path = paths.root().join("state.json");
    paths.write_file_atomically(&path, b"first", true).unwrap();
    paths.write_file_atomically(&path, b"second", true).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"second");
}

#[test]
fn failed_streamed_state_write_preserves_the_previous_value() {
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("state.json");
    atomic_write(&path, b"previous", true).unwrap();
    let result = atomic_write_with(&path, true, |file| {
        file.write_all(b"incomplete")?;
        bail!("interrupted serialization")
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"previous");
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
}
