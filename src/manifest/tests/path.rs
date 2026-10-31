use super::*;

#[test]
fn unsafe_manifest_paths_are_rejected() {
    for path in ["", "../secret", "/secret", "a\\b", "a/../../b"] {
        assert!(validate_manifest_path(path).is_err(), "{path}");
    }
}
