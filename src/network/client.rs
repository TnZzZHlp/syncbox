use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointId};
use rand::RngExt as _;
use tokio::{io::AsyncWriteExt as _, sync::Semaphore, time::timeout};
use tracing::{debug, info, warn};

use crate::{
    manifest::{Manifest, current_time_ms},
    types::{PROTOCOL_VERSION, RuntimeState, SyncHealth},
};

use super::{
    HANDSHAKE_TIMEOUT,
    auth::{make_client_hello, read_server_hello, validate_server_hello},
    io::{IO_IDLE_TIMEOUT, ProgressIo},
    run_blocking,
    scheduling::{
        MAX_CONCURRENT_PEERS, PeerSyncOutcome, SyncOutcome, select_due_peers,
        summarize_peer_outcomes,
    },
    state::{
        ActiveShare, WINDOWS_SYMLINK_ERROR, known_peer_strings, merge_remote_peers, scan_and_save,
        set_runtime_error, set_runtime_state, unsupported_symlink_count, update_runtime,
    },
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
pub async fn sync_known_peers(
    endpoint: &Endpoint,
    share: &Arc<ActiveShare>,
) -> Result<SyncOutcome> {
    let peers = share.paths.load_known_peers(share.share_id)?;
    let mut candidates = peers.endpoint_ids()?;
    candidates.retain(|endpoint_id| *endpoint_id != share.local_endpoint_id);
    if candidates.is_empty() {
        debug!(share_id = %share.share_id, "no known peers available for synchronization");
        set_runtime_state(
            share,
            RuntimeState::WaitingForPeers,
            SyncHealth::Offline,
            None,
        )?;
        return Ok(SyncOutcome::default());
    }

    let generation = share.manifest_generation.load(Ordering::Relaxed);
    let network_generation = share.network_generation.load(Ordering::Acquire);
    {
        let mut schedules = share.peer_schedule.lock().await;
        schedules.retain(|peer, _| candidates.contains(peer));
        select_due_peers(&mut candidates, &schedules, Instant::now(), generation);
        drop(schedules);
    }
    if candidates.is_empty() {
        return Ok(SyncOutcome::default());
    }
    info!(
        share_id = %share.share_id,
        candidates = candidates.len(),
        "starting synchronization with known peers"
    );
    set_runtime_state(
        share,
        RuntimeState::Synchronizing,
        SyncHealth::Pending,
        None,
    )?;
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PEERS));
    let mut tasks = tokio::task::JoinSet::new();
    for peer in candidates {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("peer semaphore is never closed");
        let endpoint = endpoint.clone();
        let share = Arc::clone(share);
        tasks.spawn(async move {
            let _permit = permit;
            info!(
                share_id = %share.share_id,
                peer_endpoint_id = %peer,
                "starting peer synchronization"
            );
            let result = sync_with_peer(&endpoint, &share, peer).await;
            let peer_outcome = result.as_ref().ok();
            let outcome = peer_outcome.map(|outcome| SyncOutcome {
                connected: true,
                pending_downloads: outcome.pending_downloads,
                pending_updates: outcome.pending_updates,
                ..SyncOutcome::default()
            });
            share
                .record_peer_attempt(peer, generation, network_generation, outcome.as_ref())
                .await;
            (peer, result)
        });
    }

    let mut had_connection_error = false;
    let mut synchronized = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((peer, Ok(peer_outcome))) => {
                synchronized = true;
                info!(
                    share_id = %share.share_id,
                    peer_endpoint_id = %peer,
                    pending_downloads = peer_outcome.pending_downloads,
                    pending_updates = peer_outcome.pending_updates,
                    "peer synchronization completed"
                );
            }
            Ok((peer, Err(error))) => {
                had_connection_error = true;
                warn!(
                    share_id = %share.share_id,
                    peer_endpoint_id = %peer,
                    error = %format_args!("{error:#}"),
                    "peer synchronization failed"
                );
                set_runtime_error(share, "could not connect to a known peer")?;
            }
            Err(error) => {
                had_connection_error = true;
                warn!(
                    share_id = %share.share_id,
                    error = %format_args!("{error:#}"),
                    "peer synchronization task failed"
                );
                set_runtime_error(share, "could not connect to a known peer")?;
            }
        }
    }
    let mut outcome = {
        let schedules = share.peer_schedule.lock().await;
        summarize_peer_outcomes(&schedules)
    };
    outcome.unsupported_items = unsupported_symlink_count(&share.manifest_snapshot()?.manifest);
    if outcome.connected {
        let completely_synchronized = outcome.pending_downloads == 0
            && outcome.pending_updates == 0
            && outcome.unsupported_items == 0;
        let (state, health) = if outcome.unsupported_items > 0 {
            (RuntimeState::Degraded, SyncHealth::Error)
        } else if completely_synchronized {
            (RuntimeState::Running, SyncHealth::Synchronized)
        } else {
            (RuntimeState::Synchronizing, SyncHealth::Pending)
        };
        update_runtime(share, |status, now_ms| {
            status.state = state;
            status.health = health;
            status.connected_peers = outcome.connected_peers;
            status.pending_downloads = outcome.pending_downloads;
            status.pending_updates = outcome.pending_updates;
            if synchronized {
                status.last_sync_at_ms = Some(now_ms);
            }
            status.last_error =
                (outcome.unsupported_items > 0).then(|| WINDOWS_SYMLINK_ERROR.to_owned());
        })?;
    } else {
        set_runtime_state(
            share,
            RuntimeState::WaitingForPeers,
            SyncHealth::Offline,
            had_connection_error.then_some("could not connect to a known peer"),
        )?;
    }
    info!(
        share_id = %share.share_id,
        connected_peers = outcome.connected_peers,
        pending_downloads = outcome.pending_downloads,
        pending_updates = outcome.pending_updates,
        unsupported_items = outcome.unsupported_items,
        "synchronization with known peers finished"
    );
    Ok(outcome)
}

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
    let (send, recv) = share
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
