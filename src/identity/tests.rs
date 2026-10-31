use tempfile::TempDir;

use super::*;

#[test]
fn identity_is_stable_after_reload() {
    let temporary = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temporary.path().join("data"));
    let first = load_or_create(&paths).unwrap().endpoint_id();
    let second = load_or_create(&paths).unwrap().endpoint_id();
    assert_eq!(first, second);
}
