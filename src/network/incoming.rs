use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream as RawRecvStream, SendStream as RawSendStream},
};
use rand::RngExt as _;
use tokio::{io::AsyncWriteExt as _, sync::Semaphore, time::timeout};
use tracing::{info, warn};

use crate::types::{PROTOCOL_VERSION, RuntimeState, SyncHealth};

use super::{
    HANDSHAKE_TIMEOUT,
    auth::{make_server_hello, read_client_hello, validate_client_hello},
    io::{IO_IDLE_TIMEOUT, ProgressIo},
    lifecycle::drain_incoming_handlers,
    registry::ShareRegistry,
    run_blocking,
    state::{
        WINDOWS_SYMLINK_ERROR, known_peer_strings, merge_remote_peers, unsupported_symlink_count,
        update_runtime,
    },
    transfer::{
        apply_remote_staged_transfer, build_transfer_files, make_transfer_ready,
        receive_upload_chunks, send_file_chunks_from_root,
    },
    transport::CONNECTION_IDLE_TIMEOUT,
    wire::{
        ManifestMessage, SyncRequest, SyncResponse, TransferRequest, TransferResponse,
        read_json_frame, validate_manifest_message, validate_sync_request,
        validate_transfer_request, write_json_frame,
    },
};
const STREAM_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn handle_incoming(
    connection: Connection,
    registry: ShareRegistry,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let peer = connection.remote_id();
    let authenticated = Arc::new(AtomicBool::new(false));
    let mut streams = tokio::task::JoinSet::new();
    loop {
        let idle_timeout = if authenticated.load(Ordering::Acquire) {
            CONNECTION_IDLE_TIMEOUT
        } else {
            HANDSHAKE_TIMEOUT
        };
        tokio::select! {
            biased;
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                if let Err(error) = result {
                    warn!(peer_endpoint_id = %peer, error = %error, "incoming stream task failed");
                }
            }
            incoming = timeout(idle_timeout, connection.accept_bi()) => {
                match incoming {
                    Ok(Ok((send, recv))) => {
                        let permit = tokio::select! {
                            _ = connection.closed() => break,
                            permit = timeout(STREAM_QUEUE_TIMEOUT, Arc::clone(&permits).acquire_owned()) => {
                                match permit {
                                    Ok(Ok(permit)) => permit,
                                    Ok(Err(_)) => break,
                                    Err(_) => continue,
                                }
                            }
                        };
                        let registry = registry.clone();
                        let authenticated = Arc::clone(&authenticated);
                        let connection = connection.clone();
                        streams.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = handle_sync_stream(peer, send, recv, registry, &authenticated).await {
                                warn!(peer_endpoint_id = %peer, error = %format_args!("{error:#}"), "incoming synchronization failed");
                                if !authenticated.load(Ordering::Acquire) {
                                    connection.close(0_u8.into(), b"sync authentication failed");
                                }
                            }
                        });
                    }
                    Ok(Err(_)) => break,
                    Err(_) if streams.is_empty() || !authenticated.load(Ordering::Acquire) => {
                        connection.close(0_u8.into(), b"sync idle");
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
    }
    drain_incoming_handlers(&mut streams).await;
    Ok(())
}

pub async fn handle_sync_stream(
    peer_endpoint_id: EndpointId,
    send: RawSendStream,
    recv: RawRecvStream,
    registry: ShareRegistry,
    authenticated: &AtomicBool,
) -> Result<()> {
    let mut send = ProgressIo::new(send, IO_IDLE_TIMEOUT);
    let mut recv = ProgressIo::new(recv, IO_IDLE_TIMEOUT);
    let client_hello = timeout(HANDSHAKE_TIMEOUT, read_client_hello(&mut recv))
        .await
        .context("timed out waiting for sync authentication")??;
    let share = registry
        .get(client_hello.share_id)
        .ok_or_else(|| anyhow!("unknown share"))?;
    let config = share.config()?;
    validate_client_hello(
        &client_hello,
        &config,
        &peer_endpoint_id,
        &share.local_endpoint_id,
    )?;
    authenticated.store(true, Ordering::Release);
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        "incoming peer authentication completed"
    );
    let server_nonce: [u8; 32] = rand::rng().random();
    let server_hello = make_server_hello(
        &config,
        &peer_endpoint_id,
        &share.local_endpoint_id,
        client_hello.nonce,
        server_nonce,
    );
    timeout(HANDSHAKE_TIMEOUT, send.write_all(&server_hello))
        .await
        .context("timed out sending sync authentication")?
        .context("unable to send sync authentication")?;

    let request: SyncRequest = read_json_frame(&mut recv).await?;
    validate_sync_request(&request, share.share_id)?;
    let (local_manifest, known_peers) = {
        let _operation_lock = share.operation_lock.lock().await;
        merge_remote_peers(&share, request.known_peers.iter(), Some(peer_endpoint_id))?;
        let local_snapshot = share.manifest_snapshot()?;
        let known_peers = known_peer_strings(&share, &peer_endpoint_id)?;
        (local_snapshot, known_peers)
    };
    let local_digest = local_manifest.digest;
    write_json_frame(
        &mut send,
        &SyncResponse {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest_digest: local_digest,
            known_peers,
        },
    )
    .await?;

    if request.manifest_digest == local_digest {
        send.inner_mut()
            .finish()
            .context("unable to finish unchanged sync stream")?;
        let _ = timeout(Duration::from_secs(5), send.inner_mut().stopped()).await;
        let unsupported_items = unsupported_symlink_count(&local_manifest.manifest);
        update_runtime(&share, |status, now_ms| {
            status.last_connection_at_ms = Some(now_ms);
            status.pending_downloads = 0;
            if unsupported_items > 0 {
                status.state = RuntimeState::Degraded;
                status.health = SyncHealth::Error;
                status.last_error = Some(WINDOWS_SYMLINK_ERROR.to_owned());
            }
        })?;
        info!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            "incoming peer manifest is unchanged"
        );
        return Ok(());
    }

    let remote_message: ManifestMessage = read_json_frame(&mut recv).await?;
    validate_manifest_message(&remote_message, share.share_id, &request.manifest_digest)?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        files = remote_message.manifest.entries.len(),
        directories = remote_message.manifest.directories.len(),
        symlinks = remote_message.manifest.symlinks.len(),
        tombstones = remote_message.manifest.tombstones.len(),
        "received incoming peer manifest"
    );
    let local_message = ManifestMessage {
        protocol_version: PROTOCOL_VERSION,
        share_id: share.share_id,
        manifest: &local_manifest.manifest,
    };
    write_json_frame(&mut send, &local_message).await?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        files = local_message.manifest.entries.len(),
        directories = local_message.manifest.directories.len(),
        symlinks = local_message.manifest.symlinks.len(),
        tombstones = local_message.manifest.tombstones.len(),
        "sent local manifest to incoming peer"
    );

    let transfer: TransferRequest = read_json_frame(&mut recv).await?;
    validate_transfer_request(&transfer, share.share_id, &remote_message.manifest)?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        uploads = transfer.uploads.len(),
        downloads = transfer.download_paths.len(),
        "received transfer request"
    );
    let (applied, final_manifest, files) = {
        let _receive_lock = share.receive_lock.lock().await;
        let ready = make_transfer_ready(&share, &transfer, &remote_message.manifest)?;
        write_json_frame(&mut send, &ready).await?;
        let uploaded = receive_upload_chunks(
            &share,
            peer_endpoint_id,
            share.share_id,
            &transfer.uploads,
            &ready.uploads,
            &mut recv,
        )
        .await?;
        let _operation_lock = share.operation_lock.lock().await;
        let applied = run_blocking(|| {
            apply_remote_staged_transfer(&share, &remote_message.manifest, &uploaded)
        })?;
        let final_manifest = share.manifest_snapshot()?;
        let files = build_transfer_files(
            &final_manifest.manifest,
            &transfer.download_paths,
            &transfer.download_resumes,
        )?;
        info!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            applied_records = applied.applied_records,
            pending_downloads = applied.pending_downloads,
            unsupported_items = applied.unsupported_items,
            response_files = files.len(),
            "applied incoming peer transfer"
        );
        (applied, final_manifest, files)
    };
    write_json_frame(
        &mut send,
        &TransferResponse {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest: &final_manifest.manifest,
            files: &files,
        },
    )
    .await?;
    send_file_chunks_from_root(&share, peer_endpoint_id, &files, &mut send).await?;
    send.inner_mut()
        .finish()
        .context("unable to finish sync response stream")?;
    // Keep the connection alive until the client has acknowledged the final response. Dropping an
    // Iroh connection immediately after finish can abandon buffered stream data.
    let _ = timeout(Duration::from_secs(5), send.inner_mut().stopped()).await;
    update_runtime(&share, |status, now_ms| {
        status.last_connection_at_ms = Some(now_ms);
        if applied.applied_records > 0 {
            status.last_remote_update_at_ms = Some(now_ms);
        }
        status.pending_downloads = applied.pending_downloads;
        if applied.unsupported_items > 0 {
            status.state = RuntimeState::Degraded;
            status.health = SyncHealth::Error;
            status.last_error = Some(WINDOWS_SYMLINK_ERROR.to_owned());
        }
    })?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        "incoming synchronization finished"
    );
    Ok(())
}
