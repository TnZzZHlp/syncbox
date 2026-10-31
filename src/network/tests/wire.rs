use super::*;

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
