use super::*;

#[test]
fn borrowed_transfer_ready_preserves_the_existing_wire_message() {
    let share_id = ShareId([85; 32]);
    let owned = TransferReady {
        protocol_version: PROTOCOL_VERSION,
        share_id,
        uploads: vec![TransferFile {
            path: "file".to_owned(),
            sha256: "a".repeat(64),
            size: 8,
            offset: 3,
        }],
    };
    let borrowed = TransferReady {
        protocol_version: PROTOCOL_VERSION,
        share_id,
        uploads: owned.uploads.as_slice(),
    };
    let encoded = serde_json::to_vec(&borrowed).unwrap();
    assert_eq!(encoded, serde_json::to_vec(&owned).unwrap());
    let decoded: TransferReady = serde_json::from_slice(&encoded).unwrap();
    validate_transfer_ready(&decoded, share_id, &owned.uploads).unwrap();
    assert_eq!(decoded.uploads[0].offset, 3);
}

#[test]
fn transfer_request_rejects_a_resume_outside_its_validated_paths() {
    let share_id = ShareId([103; 32]);
    let manifest = Manifest::empty(share_id, 1);
    let mut request = TransferRequest {
        protocol_version: PROTOCOL_VERSION,
        share_id,
        download_paths: vec!["file".to_owned()],
        download_resumes: vec![TransferFile {
            path: "file".to_owned(),
            sha256: "a".repeat(64),
            size: 8,
            offset: 3,
        }],
        uploads: Vec::new(),
    };
    validate_transfer_request(&request, share_id, &manifest).unwrap();
    request.download_resumes[0].path = "other".to_owned();
    assert_eq!(
        validate_transfer_request(&request, share_id, &manifest)
            .unwrap_err()
            .to_string(),
        "network transfer resume path was not requested"
    );
}

#[test]
fn sync_request_carries_only_the_manifest_digest() {
    let share_id = ShareId([42; 32]);
    let manifest = Manifest::empty(share_id, 1);
    let digest = manifest.sync_digest(share_id).unwrap();
    let request = SyncRequest {
        protocol_version: PROTOCOL_VERSION,
        share_id,
        manifest_digest: digest,
        known_peers: Vec::new(),
    };
    let encoded = serde_json::to_value(&request).unwrap();

    assert!(encoded.get("manifest").is_none());
    assert!(encoded.get("manifest_digest").is_some());
    validate_sync_request(&request, share_id).unwrap();
    validate_manifest_message(
        &ManifestMessage {
            protocol_version: PROTOCOL_VERSION,
            share_id,
            manifest,
        },
        share_id,
        &digest,
    )
    .unwrap();
}
