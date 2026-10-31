use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointId};
use rand::RngExt as _;
use tokio::{io::AsyncWriteExt as _, time::timeout};
use tracing::info;

use crate::{
    manifest::{Manifest, current_time_ms},
    types::PROTOCOL_VERSION,
};

use super::{
    HANDSHAKE_TIMEOUT,
    auth::{make_client_hello, read_server_hello, validate_server_hello},
    io::{IO_IDLE_TIMEOUT, ProgressIo},
    run_blocking,
    scheduling::PeerSyncOutcome,
    state::{ActiveShare, known_peer_strings, merge_remote_peers, scan_and_save, update_runtime},
    transfer::{
        apply_remote_staged_transfer, make_transfer_request, receive_download_chunks,
        send_upload_chunks,
    },
    wire::{
        ManifestMessage, SyncRequest, SyncResponse, TransferReady, TransferResponse,
        read_json_frame, validate_manifest_message, validate_sync_response,
        validate_transfer_ready, validate_transfer_response, write_json_frame,
    },
};
pub async fn sync_with_peer(
    endpoint: &Endpoint,
    share: &Arc<ActiveShare>,
    expected_peer: EndpointId,
) -> Result<PeerSyncOutcome> {
    let config = share.config()?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        "connecting to peer"
    );
    let (send, recv, _lease) = share
        .connections
        .open_stream(endpoint, expected_peer)
        .await?;
    let mut send = ProgressIo::new(send, IO_IDLE_TIMEOUT);
    let mut recv = ProgressIo::new(recv, IO_IDLE_TIMEOUT);
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        "connected to peer"
    );
    update_runtime(share, |status, now_ms| {
        status.connected_peers = 1;
        status.last_connection_at_ms = Some(now_ms);
    })?;

    let nonce: [u8; 32] = rand::rng().random();
    let client_hello = make_client_hello(&config, &share.local_endpoint_id, &expected_peer, nonce);
    let server_hello = timeout(HANDSHAKE_TIMEOUT, async {
        send.write_all(&client_hello)
            .await
            .context("unable to send sync authentication")?;
        read_server_hello(&mut recv).await
    })
    .await
    .context("timed out waiting for peer authentication")??;
    validate_server_hello(
        &server_hello,
        &config,
        &share.local_endpoint_id,
        &expected_peer,
        nonce,
    )?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        "peer authentication completed"
    );

    let outbound_snapshot = config
        .initial_sync_complete
        .then(|| share.manifest_snapshot())
        .transpose()?;
    let outbound_digest = match &outbound_snapshot {
        Some(snapshot) => snapshot.digest,
        None => Manifest::empty(share.share_id, current_time_ms()).sync_digest(share.share_id)?,
    };
    let known_peers = known_peer_strings(share, &expected_peer)?;
    write_json_frame(
        &mut send,
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest_digest: outbound_digest,
            known_peers,
        },
    )
    .await?;
    let response: SyncResponse = read_json_frame(&mut recv).await?;
    validate_sync_response(&response, share.share_id)?;

    {
        let _operation_lock = share.operation_lock.lock().await;
        merge_remote_peers(share, response.known_peers.iter(), Some(expected_peer))?;
    }
    if response.manifest_digest == outbound_digest {
        if !config.initial_sync_complete {
            let _operation_lock = share.operation_lock.lock().await;
            let mut updated_config = share.config()?;
            if !updated_config.initial_sync_complete {
                updated_config.initial_sync_complete = true;
                share.paths.save_config(&updated_config)?;
                share.replace_config(updated_config.clone())?;
                run_blocking(|| scan_and_save(share, &updated_config))?;
            }
        }
        send.inner_mut()
            .finish()
            .context("unable to finish unchanged sync stream")?;
        info!(
            share_id = %share.share_id,
            peer_endpoint_id = %expected_peer,
            "peer manifests are unchanged"
        );
        return Ok(PeerSyncOutcome {
            pending_downloads: 0,
            pending_updates: 0,
        });
    }

    let empty_manifest = Manifest::empty(share.share_id, current_time_ms());
    let outbound_manifest = outbound_snapshot
        .as_ref()
        .map_or(&empty_manifest, |snapshot| &snapshot.manifest);
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        files = outbound_manifest.entries.len(),
        directories = outbound_manifest.directories.len(),
        symlinks = outbound_manifest.symlinks.len(),
        tombstones = outbound_manifest.tombstones.len(),
        "sending local manifest"
    );
    let outbound_message = ManifestMessage {
        protocol_version: PROTOCOL_VERSION,
        share_id: share.share_id,
        manifest: outbound_manifest,
    };
    write_json_frame(&mut send, &outbound_message).await?;
    let remote_message: ManifestMessage = read_json_frame(&mut recv).await?;
    validate_manifest_message(&remote_message, share.share_id, &response.manifest_digest)?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        files = remote_message.manifest.entries.len(),
        directories = remote_message.manifest.directories.len(),
        symlinks = remote_message.manifest.symlinks.len(),
        tombstones = remote_message.manifest.tombstones.len(),
        "received peer manifest"
    );

    let (transfer, pending_updates) = {
        let _operation_lock = share.operation_lock.lock().await;
        make_transfer_request(share, outbound_message.manifest, &remote_message.manifest)?
    };
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        uploads = transfer.uploads.len(),
        downloads = transfer.download_paths.len(),
        pending_updates,
        "prepared transfer request"
    );
    write_json_frame(&mut send, &transfer).await?;
    let ready: TransferReady = read_json_frame(&mut recv).await?;
    validate_transfer_ready(&ready, share.share_id, &transfer.uploads)?;
    send_upload_chunks(
        share,
        expected_peer,
        &transfer.uploads,
        &ready.uploads,
        &mut send,
    )
    .await?;
    send.inner_mut()
        .finish()
        .context("unable to finish upload stream")?;
    let final_response: TransferResponse = read_json_frame(&mut recv).await?;
    validate_transfer_response(&final_response, share.share_id)?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        downloads = final_response.files.len(),
        "received transfer response"
    );
    let applied = {
        let _receive_lock = share.receive_lock.lock().await;
        let completed =
            receive_download_chunks(share, expected_peer, &final_response.files, &mut recv).await?;
        let _operation_lock = share.operation_lock.lock().await;
        let applied = run_blocking(|| {
            apply_remote_staged_transfer(share, &final_response.manifest, &completed)
        })?;
        if applied.applied_records > 0 {
            update_runtime(share, |status, now_ms| {
                status.last_remote_update_at_ms = Some(now_ms);
            })?;
        }

        let mut updated_config = share.config()?;
        if !updated_config.initial_sync_complete && applied.pending_downloads == 0 {
            updated_config.initial_sync_complete = true;
            share.paths.save_config(&updated_config)?;
            share.replace_config(updated_config.clone())?;
            // Only scan after the remote snapshot has been applied. Remote entries retain their
            // version, while files that existed only in the join target receive fresh local
            // versions.
            run_blocking(|| scan_and_save(share, &updated_config))?;
        }
        info!(
            share_id = %share.share_id,
            peer_endpoint_id = %expected_peer,
            applied_records = applied.applied_records,
            pending_downloads = applied.pending_downloads,
            unsupported_items = applied.unsupported_items,
            "applied peer transfer"
        );
        applied
    };
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        "peer synchronization finished"
    );
    Ok(PeerSyncOutcome {
        pending_downloads: applied.pending_downloads,
        pending_updates,
    })
}
