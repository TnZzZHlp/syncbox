use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn syncbox() -> Command {
    Command::cargo_bin("syncbox").unwrap()
}

#[test]
fn init_and_status_keep_state_outside_the_shared_directory() {
    let temporary = TempDir::new().unwrap();
    let shared_directory = temporary.path().join("shared");
    let data_directory = temporary.path().join("data");
    fs::create_dir_all(&shared_directory).unwrap();
    fs::write(shared_directory.join("config.txt"), "value").unwrap();

    let output = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args([
            "init",
            shared_directory.to_str().unwrap(),
            "--name",
            "config",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Shared directory registered"));
    assert!(output.contains("Join ticket:\nsyncbox1:"));
    assert!(!shared_directory.join(".syncbox").exists());
    assert!(data_directory.join("identity/device.key").exists());
    assert!(data_directory.join("shares").is_dir());

    let output = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    let shares = value["shares"].as_array().unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0]["name"], "config");
    assert_eq!(shares[0]["files"], 1);
    assert_eq!(shares[0]["runtime"], "stopped");
    assert!(shares[0].get("share_secret").is_none());
}

#[test]
fn remove_unregisters_share_and_preserves_local_files() {
    let temporary = TempDir::new().unwrap();
    let shared_directory = temporary.path().join("shared");
    let data_directory = temporary.path().join("data");
    fs::create_dir_all(&shared_directory).unwrap();
    fs::write(shared_directory.join("keep.txt"), "keep").unwrap();
    syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["init", shared_directory.to_str().unwrap()])
        .assert()
        .success();
    let status = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status).unwrap();
    let share_id = status["shares"][0]["share_id"].as_str().unwrap();

    let output = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["remove", &share_id[..8]])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Shared directory registration removed"));
    assert!(output.contains("Local directory and files were left unchanged"));
    assert_eq!(
        fs::read_to_string(shared_directory.join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(!data_directory.join("shares").join(share_id).exists());
    let status = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status).unwrap();
    assert_eq!(status, serde_json::json!({ "shares": [] }));
}

#[test]
fn status_on_an_empty_data_directory_is_machine_readable() {
    let temporary = TempDir::new().unwrap();
    let data_directory = temporary.path().join("data");
    let output = syncbox()
        .env("SYNCBOX_DATA_DIR", &data_directory)
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value, serde_json::json!({ "shares": [] }));
    assert!(!data_directory.exists());
}
