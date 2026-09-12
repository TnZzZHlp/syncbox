use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use iroh::{
    Endpoint, EndpointId, RelayMode,
    address_lookup::{AddrFilter, DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use rand::Rng as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, warn};

use crate::{
    identity::DeviceIdentity,
    manifest::{
        Manifest, ManifestRecordRef, current_time_ms, path_for_manifest, scan_manifest,
        select_record, validate_manifest_path,
    },
    storage::DataPaths,
    types::{
        PROTOCOL_VERSION, RuntimeState, RuntimeStatus, ShareConfig, ShareId, SyncHealth,
        parse_endpoint_id,
    },
};

pub const SYNCBOX_ALPN: &[u8] = b"syncbox/2";
const AUTH_MAGIC: [u8; 4] = *b"SBXA";
const CLIENT_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32;
const SERVER_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32 + 32;
const MAX_CONTROL_FRAME_BYTES: usize = 96 * 1024 * 1024;
const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_TRANSFER_FILES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SYNC_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INCOMING_HANDLERS: usize = 32;
// ponytail: four concurrent shares; tune after multi-share throughput measurements.
const MAX_CONCURRENT_SHARES: usize = 4;
// ponytail: two concurrent peer sessions; tune after per-share I/O measurements.
const MAX_CONCURRENT_PEERS: usize = 2;
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

type HmacSha256 = Hmac<Sha256>;

async fn bind_endpoint(
    secret_key: iroh::SecretKey,
) -> std::result::Result<Endpoint, iroh::endpoint::BindError> {
    Endpoint::builder(presets::N0DisableRelay)
        .clear_address_lookup()
        .address_lookup(PkarrPublisher::n0_dns().addr_filter(AddrFilter::unfiltered()))
        .address_lookup(PkarrResolver::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .relay_mode(RelayMode::Disabled)
        .secret_key(secret_key)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
}

#[derive(Clone)]
struct ActiveShare {
    paths: DataPaths,
    share_id: ShareId,
    config: Arc<RwLock<ShareConfig>>,
    receive_lock: Arc<Mutex<()>>,
    operation_lock: Arc<Mutex<()>>,
    status_lock: Arc<std::sync::Mutex<()>>,
    local_endpoint_id: EndpointId,
}

impl ActiveShare {
    fn config(&self) -> Result<ShareConfig> {
        self.config
            .read()
            .map_err(|_| anyhow!("share configuration lock was poisoned"))
            .map(|config| config.clone())
    }

    fn replace_config(&self, config: ShareConfig) -> Result<()> {
        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("share configuration lock was poisoned"))?;
        *guard = config;
        drop(guard);
        Ok(())
    }
}

#[derive(Clone)]
struct ShareRegistry {
    shares: Arc<HashMap<ShareId, Arc<ActiveShare>>>,
}

impl ShareRegistry {
    fn get(&self, share_id: ShareId) -> Option<Arc<ActiveShare>> {
        self.shares.get(&share_id).cloned()
    }

    fn values(&self) -> impl Iterator<Item = Arc<ActiveShare>> + '_ {
        self.shares.values().cloned()
    }
}

pub async fn run(
    paths: DataPaths,
    identity: DeviceIdentity,
    share_ids: Vec<ShareId>,
    once: bool,
) -> Result<()> {
    let registry = load_registry(&paths, identity.endpoint_id(), &share_ids)?;
    if registry.shares.is_empty() {
        return Ok(());
    }

    info!(
        shares = registry.shares.len(),
        once, "starting synchronization"
    );
    for share in registry.values() {
        set_runtime_state(&share, RuntimeState::Starting, SyncHealth::Unknown, None)?;
    }

    let endpoint = match bind_endpoint(identity.secret_key()).await {
        Ok(endpoint) => {
            info!("Iroh endpoint started");
            endpoint
        }
        Err(error) => {
            error!(
                error = %format_args!("{error:#}"),
                "unable to start the global Iroh endpoint"
            );
            for share in registry.values() {
                let _ = set_runtime_error(&share, "unable to start Iroh endpoint");
            }
            return Err(anyhow!(error).context("unable to start the global Iroh endpoint"));
        }
    };

    let accept_task = spawn_accept_loop(endpoint.clone(), registry.clone());
    let result = run_cycles(&endpoint, &registry, once).await;
    endpoint.close().await;
    if let Err(error) = accept_task.await {
        warn!(
            error = %format_args!("{error:#}"),
            "incoming accept loop failed during shutdown"
        );
    }
    for share in registry.values() {
        let _ = set_stopped(&share);
    }
    info!("synchronization stopped");
    result
}

/// Attempts the mandatory initial peer connection after `join` has already persisted its state.
/// Connection failures are normal: callers receive `Ok(false)` and retain the ticket data.
pub async fn attempt_initial_sync(
    paths: DataPaths,
    identity: DeviceIdentity,
    share_id: ShareId,
) -> Result<bool> {
    let Some(_device_lock) = paths.try_acquire_device_run_lock()? else {
        return Ok(false);
    };
    let Some(_share_lock) = paths.try_acquire_share_lock(share_id)? else {
        return Ok(false);
    };
    let registry = load_registry(&paths, identity.endpoint_id(), &[share_id])?;
    let Some(share) = registry.get(share_id) else {
        return Ok(false);
    };
    set_runtime_state(
        &share,
        RuntimeState::Synchronizing,
        SyncHealth::Pending,
        None,
    )?;
    let endpoint = match bind_endpoint(identity.secret_key()).await {
        Ok(endpoint) => endpoint,
        Err(error) => {
            warn!(
                share_id = %share_id,
                error = %format_args!("{error:#}"),
                "unable to start Iroh endpoint for initial sync"
            );
            set_runtime_state(
                &share,
                RuntimeState::WaitingForPeers,
                SyncHealth::Offline,
                None,
            )?;
            return Ok(false);
        }
    };
    let result = sync_known_peers(&endpoint, &share).await;
    endpoint.close().await;
    match result {
        Ok(outcome) if outcome.connected => {
            info!(share_id = %share_id, "initial synchronization connected");
            set_stopped(&share)?;
            Ok(true)
        }
        Ok(_) => {
            info!(share_id = %share_id, "initial synchronization found no online peers");
            set_runtime_state(
                &share,
                RuntimeState::WaitingForPeers,
                SyncHealth::Offline,
                None,
            )?;
            Ok(false)
        }
        Err(error) => {
            warn!(
                share_id = %share_id,
                error = %format_args!("{error:#}"),
                "initial synchronization failed"
            );
            set_runtime_state(
                &share,
                RuntimeState::WaitingForPeers,
                SyncHealth::Offline,
                None,
            )?;
            Ok(false)
        }
    }
}

fn load_registry(
    paths: &DataPaths,
    endpoint_id: EndpointId,
    share_ids: &[ShareId],
) -> Result<ShareRegistry> {
    let mut shares = HashMap::new();
    for share_id in share_ids {
        let config = paths.load_config(*share_id)?;
        shares.insert(
            *share_id,
            Arc::new(ActiveShare {
                paths: paths.clone(),
                share_id: *share_id,
                config: Arc::new(RwLock::new(config)),
                receive_lock: Arc::new(Mutex::new(())),
                operation_lock: Arc::new(Mutex::new(())),
                status_lock: Arc::new(std::sync::Mutex::new(())),
                local_endpoint_id: endpoint_id,
            }),
        );
    }
    Ok(ShareRegistry {
        shares: Arc::new(shares),
    })
}

async fn drain_incoming_handlers(handlers: &mut tokio::task::JoinSet<()>) {
    while let Some(result) = handlers.join_next().await {
        if let Err(error) = result {
            warn!(
                error = %format_args!("{error:#}"),
                "incoming synchronization task failed"
            );
        }
    }
}

fn spawn_accept_loop(endpoint: Endpoint, registry: ShareRegistry) -> JoinHandle<()> {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(MAX_INCOMING_HANDLERS));
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = result {
                        warn!(
                            error = %format_args!("{error:#}"),
                            "incoming synchronization task failed"
                        );
                    }
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    // Drop excess unauthenticated connections rather than allowing stalled peers
                    // to create unbounded tasks or consume every stream handler.
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        continue;
                    };
                    let registry = registry.clone();
                    handlers.spawn(async move {
                        let _permit = permit;
                        let connection = match timeout(HANDSHAKE_TIMEOUT, incoming).await {
                            Ok(Ok(connection)) => connection,
                            Ok(Err(error)) => {
                                warn!(
                                    error = %format_args!("{error:#}"),
                                    "incoming connection failed during handshake"
                                );
                                return;
                            }
                            Err(error) => {
                                warn!(
                                    error = %format_args!("{error:#}"),
                                    "incoming connection handshake timed out"
                                );
                                return;
                            }
                        };
                        let peer_endpoint_id = connection.remote_id();
                        if let Err(error) = handle_incoming(connection, registry).await {
                            warn!(
                                peer_endpoint_id = %peer_endpoint_id,
                                error = %format_args!("{error:#}"),
                                "incoming synchronization failed"
                            );
                        }
                    });
                }
            }
        }
        drain_incoming_handlers(&mut handlers).await;
    })
}

async fn run_cycles(endpoint: &Endpoint, registry: &ShareRegistry, once: bool) -> Result<()> {
    // Connection and transfer deadlines may be much longer than the status freshness window.
    // Refresh status independently so a healthy process is never reported as stopped merely
    // because one peer is slow or unreachable.
    let heartbeat_task = spawn_heartbeat_loop(registry.clone());
    let result = if run_sync_cycle_until_shutdown(endpoint, registry).await? {
        if once {
            Ok(())
        } else {
            run_periodic_cycles(endpoint, registry).await
        }
    } else {
        Ok(())
    };
    heartbeat_task.abort();
    let _ = heartbeat_task.await;
    result
}

async fn run_periodic_cycles(endpoint: &Endpoint, registry: &ShareRegistry) -> Result<()> {
    loop {
        tokio::select! {
            shutdown = wait_for_shutdown_signal() => {
                shutdown?;
                return Ok(());
            }
            () = tokio::time::sleep(SYNC_INTERVAL) => {}
        }
        // A cycle may be waiting for a peer. Keep shutdown responsive instead of postponing a
        // service-manager signal until connection and transfer deadlines expire.
        if !run_sync_cycle_until_shutdown(endpoint, registry).await? {
            return Ok(());
        }
    }
}

async fn run_sync_cycle_until_shutdown(
    endpoint: &Endpoint,
    registry: &ShareRegistry,
) -> Result<bool> {
    // Keep the cycle future alive after shutdown wins. Its JoinSet owns work that may be inside
    // block_in_place, which Tokio cannot cancel.
    let cycle = run_sync_cycle(endpoint, registry);
    tokio::pin!(cycle);
    tokio::select! {
        shutdown = wait_for_shutdown_signal() => {
            let shutdown_result = shutdown;
            cycle.await;
            shutdown_result?;
            Ok(false)
        }
        () = &mut cycle => Ok(true),
    }
}

fn spawn_heartbeat_loop(registry: ShareRegistry) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            heartbeat.tick().await;
            for share in registry.values() {
                let _ = refresh_heartbeat(&share);
            }
        }
    })
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("unable to register SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("unable to wait for Ctrl-C")?;
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("unable to wait for Ctrl-C")?;
    }
    Ok(())
}

async fn run_sync_cycle(endpoint: &Endpoint, registry: &ShareRegistry) {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_SHARES));
    let mut tasks = tokio::task::JoinSet::new();
    for share in registry.values() {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("share semaphore is never closed");
        let endpoint = endpoint.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let share_id = share.share_id;
            let result = sync_active_share(&endpoint, &share).await;
            (share_id, result)
        });
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((share_id, Err(error))) => {
                error!(
                    share_id = %share_id,
                    error = %format_args!("{error:#}"),
                    "synchronization cycle failed"
                );
            }
            Ok((_share_id, Ok(()))) => {}
            Err(error) => {
                error!(
                    error = %format_args!("{error:#}"),
                    "synchronization task failed"
                );
            }
        }
    }
}

fn run_blocking<T>(operation: impl FnOnce() -> T) -> T {
    if matches!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

async fn sync_active_share(endpoint: &Endpoint, share: &Arc<ActiveShare>) -> Result<()> {
    let config = share.config()?;
    if config.initial_sync_complete {
        // Keep the operation lock held while blocking work runs; a detached blocking task could
        // outlive a cancelled synchronization cycle during shutdown.
        let _operation_lock = share.operation_lock.lock().await;
        run_blocking(|| scan_and_save(share, &config))?;
    }
    sync_known_peers(endpoint, share).await.map(|_| ())
}

#[derive(Default)]
struct SyncOutcome {
    connected: bool,
    connected_peers: usize,
    pending_downloads: usize,
    pending_updates: usize,
}

struct PeerSyncOutcome {
    pending_downloads: usize,
    pending_updates: usize,
}

struct ApplyOutcome {
    pending_downloads: usize,
    applied_records: usize,
}

async fn sync_known_peers(endpoint: &Endpoint, share: &Arc<ActiveShare>) -> Result<SyncOutcome> {
    let peers = share.paths.load_known_peers(share.share_id)?;
    let mut candidates = peers.endpoint_ids()?;
    candidates.retain(|endpoint_id| *endpoint_id != share.local_endpoint_id);
    candidates.truncate(4);
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
            let result = timeout(
                SYNC_EXCHANGE_TIMEOUT,
                sync_with_peer(&endpoint, &share, peer),
            )
            .await;
            (peer, result)
        });
    }

    let mut outcome = SyncOutcome::default();
    let mut had_connection_error = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((peer, Ok(Ok(peer_outcome)))) => {
                info!(
                    share_id = %share.share_id,
                    peer_endpoint_id = %peer,
                    pending_downloads = peer_outcome.pending_downloads,
                    pending_updates = peer_outcome.pending_updates,
                    "peer synchronization completed"
                );
                outcome.connected = true;
                outcome.connected_peers = outcome.connected_peers.saturating_add(1);
                outcome.pending_downloads = outcome
                    .pending_downloads
                    .saturating_add(peer_outcome.pending_downloads);
                outcome.pending_updates = outcome
                    .pending_updates
                    .saturating_add(peer_outcome.pending_updates);
            }
            Ok((peer, Ok(Err(error)))) => {
                had_connection_error = true;
                warn!(
                    share_id = %share.share_id,
                    peer_endpoint_id = %peer,
                    error = %format_args!("{error:#}"),
                    "peer synchronization failed"
                );
                set_runtime_error(share, "could not connect to a known peer")?;
            }
            Ok((peer, Err(error))) => {
                had_connection_error = true;
                warn!(
                    share_id = %share.share_id,
                    peer_endpoint_id = %peer,
                    error = %format_args!("{error:#}"),
                    "peer synchronization timed out"
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
    if outcome.connected {
        let completely_synchronized =
            outcome.pending_downloads == 0 && outcome.pending_updates == 0;
        let health = if completely_synchronized {
            SyncHealth::Synchronized
        } else {
            SyncHealth::Pending
        };
        let state = if completely_synchronized {
            RuntimeState::Running
        } else {
            RuntimeState::Synchronizing
        };
        update_runtime(share, |status, now_ms| {
            status.state = state;
            status.health = health;
            status.connected_peers = outcome.connected_peers;
            status.pending_downloads = outcome.pending_downloads;
            status.pending_updates = outcome.pending_updates;
            status.last_sync_at_ms = Some(now_ms);
            status.last_error = None;
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
        "synchronization with known peers finished"
    );
    Ok(outcome)
}

async fn sync_with_peer(
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
    let connection = timeout(
        CONNECT_TIMEOUT,
        endpoint.connect(expected_peer, SYNCBOX_ALPN),
    )
    .await
    .context("timed out connecting to known Iroh endpoint")?
    .context("unable to connect to known Iroh endpoint")?;
    if connection.remote_id() != expected_peer {
        bail!("connected Iroh endpoint does not match the expected peer");
    }
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %expected_peer,
        "connected to peer"
    );
    update_runtime(share, |status, now_ms| {
        status.connected_peers = 1;
        status.last_connection_at_ms = Some(now_ms);
    })?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("unable to open sync stream")?;
    let nonce: [u8; 32] = rand::rng().random();
    let client_hello = make_client_hello(&config, &share.local_endpoint_id, &expected_peer, nonce);
    send.write_all(&client_hello)
        .await
        .context("unable to send sync authentication")?;
    let server_hello = read_server_hello(&mut recv).await?;
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

    let outbound_manifest = if config.initial_sync_complete {
        share.paths.load_manifest(share.share_id)?
    } else {
        Manifest::empty(share.share_id, current_time_ms())
    };
    let outbound_digest = if config.initial_sync_complete {
        outbound_manifest.sync_digest_after_validation()
    } else {
        outbound_manifest.sync_digest(share.share_id)?
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
        send.finish()
            .context("unable to finish unchanged sync stream")?;
        connection.close(0_u8.into(), b"sync unchanged");
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
        make_transfer_request(share, &outbound_message.manifest, &remote_message.manifest)?
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
    send.finish().context("unable to finish upload stream")?;
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
            "applied peer transfer"
        );
        applied
    };
    connection.close(0_u8.into(), b"sync complete");
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

async fn handle_incoming(connection: Connection, registry: ShareRegistry) -> Result<()> {
    let peer_endpoint_id = connection.remote_id();
    info!(
        peer_endpoint_id = %peer_endpoint_id,
        "accepted incoming synchronization connection"
    );
    let (mut send, mut recv) = timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .context("timed out waiting for sync stream")?
        .context("unable to accept sync stream")?;
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
    send.write_all(&server_hello)
        .await
        .context("unable to send sync authentication")?;

    let request: SyncRequest = read_json_frame(&mut recv).await?;
    validate_sync_request(&request, share.share_id)?;
    let (local_manifest, known_peers) = {
        let _operation_lock = share.operation_lock.lock().await;
        merge_remote_peers(&share, request.known_peers.iter(), Some(peer_endpoint_id))?;
        let local_manifest = share.paths.load_manifest(share.share_id)?;
        let known_peers = known_peer_strings(&share, &peer_endpoint_id)?;
        (local_manifest, known_peers)
    };
    let local_digest = local_manifest.sync_digest_after_validation();
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
        send.finish()
            .context("unable to finish unchanged sync stream")?;
        let _ = timeout(Duration::from_secs(5), send.stopped()).await;
        update_runtime(&share, |status, now_ms| {
            status.last_connection_at_ms = Some(now_ms);
            status.pending_downloads = 0;
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
        manifest: local_manifest,
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
        let final_manifest = share.paths.load_manifest(share.share_id)?;
        let files = build_transfer_files(
            &final_manifest,
            &transfer.download_paths,
            &transfer.download_resumes,
        )?;
        info!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            applied_records = applied.applied_records,
            pending_downloads = applied.pending_downloads,
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
            manifest: final_manifest,
            files: files.clone(),
        },
    )
    .await?;
    send_file_chunks_from_root(&share, peer_endpoint_id, &files, &mut send).await?;
    send.finish()
        .context("unable to finish sync response stream")?;
    // Keep the connection alive until the client has acknowledged the final response. Dropping an
    // Iroh connection immediately after finish can abandon buffered stream data.
    let _ = timeout(Duration::from_secs(5), send.stopped()).await;
    update_runtime(&share, |status, now_ms| {
        status.last_connection_at_ms = Some(now_ms);
        if applied.applied_records > 0 {
            status.last_remote_update_at_ms = Some(now_ms);
        }
        status.pending_downloads = applied.pending_downloads;
    })?;
    info!(
        share_id = %share.share_id,
        peer_endpoint_id = %peer_endpoint_id,
        "incoming synchronization finished"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncRequest {
    protocol_version: u16,
    share_id: ShareId,
    manifest_digest: [u8; 32],
    known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncResponse {
    protocol_version: u16,
    share_id: ShareId,
    manifest_digest: [u8; 32],
    known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestMessage {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferRequest {
    protocol_version: u16,
    share_id: ShareId,
    download_paths: Vec<String>,
    download_resumes: Vec<TransferFile>,
    uploads: Vec<TransferFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferReady {
    protocol_version: u16,
    share_id: ShareId,
    uploads: Vec<TransferFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferResponse {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
    files: Vec<TransferFile>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferFile {
    path: String,
    sha256: String,
    size: u64,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkFrame {
    path: String,
    sha256: String,
    offset: u64,
    content: String,
}

#[derive(Serialize)]
struct OutgoingChunkFrame<'a> {
    path: &'a str,
    sha256: &'a str,
    offset: u64,
    content: &'a str,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePayload {
    path: String,
    sha256: String,
    content: String,
}

fn validate_sync_request(request: &SyncRequest, share_id: ShareId) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION || request.share_id != share_id {
        bail!("sync request has an incompatible protocol or share ID");
    }
    validate_wire_peers(&request.known_peers)
}

fn validate_sync_response(response: &SyncResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("sync response has an incompatible protocol or share ID");
    }
    validate_wire_peers(&response.known_peers)
}

fn validate_manifest_message(
    message: &ManifestMessage,
    share_id: ShareId,
    expected_digest: &[u8; 32],
) -> Result<()> {
    if message.protocol_version != PROTOCOL_VERSION || message.share_id != share_id {
        bail!("manifest message has an incompatible protocol or share ID");
    }
    if message.manifest.sync_digest(share_id)? != *expected_digest {
        bail!("manifest message does not match its advertised digest");
    }
    Ok(())
}

fn validate_transfer_request(
    request: &TransferRequest,
    share_id: ShareId,
    manifest: &Manifest,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION || request.share_id != share_id {
        bail!("file transfer request has an incompatible protocol or share ID");
    }
    manifest.validate(share_id)?;
    validate_path_list(&request.download_paths)?;
    validate_transfer_files(&request.uploads, manifest)?;
    validate_transfer_file_shapes(&request.download_resumes)?;
    let requested_downloads = request.download_paths.iter().collect::<HashSet<_>>();
    for resume in &request.download_resumes {
        if !requested_downloads.contains(&resume.path) {
            bail!("network transfer resume path was not requested");
        }
    }
    Ok(())
}

fn validate_transfer_ready(
    ready: &TransferReady,
    share_id: ShareId,
    requested: &[TransferFile],
) -> Result<()> {
    if ready.protocol_version != PROTOCOL_VERSION || ready.share_id != share_id {
        bail!("file transfer ready message has an incompatible protocol or share ID");
    }
    validate_transfer_file_shapes(&ready.uploads)?;
    if ready.uploads.len() != requested.len() {
        bail!("file transfer ready message has an unexpected upload count");
    }
    for (actual, expected) in ready.uploads.iter().zip(requested) {
        if actual.path != expected.path
            || actual.sha256 != expected.sha256
            || actual.size != expected.size
        {
            bail!("file transfer ready message does not match the request");
        }
    }
    Ok(())
}

fn validate_transfer_response(response: &TransferResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("file transfer response has an incompatible protocol or share ID");
    }
    response.manifest.validate(share_id)?;
    validate_transfer_files(&response.files, &response.manifest)
}

fn validate_transfer_file_shapes(files: &[TransferFile]) -> Result<()> {
    if files.len() > MAX_TRANSFER_FILES {
        bail!("network transfer contains too many files");
    }
    let mut unique = HashSet::new();
    for file in files {
        validate_manifest_path(&file.path)?;
        validate_sha256(&file.sha256)?;
        if file.offset > file.size {
            bail!("network transfer resume offset exceeds file size");
        }
        if !unique.insert(&file.path) {
            bail!("network transfer contains duplicate file paths");
        }
    }
    Ok(())
}

fn validate_transfer_files(files: &[TransferFile], manifest: &Manifest) -> Result<()> {
    validate_transfer_file_shapes(files)?;
    for file in files {
        let entry = manifest
            .entries
            .get(&file.path)
            .ok_or_else(|| anyhow!("network transfer file is not present in its manifest"))?;
        if entry.sha256 != file.sha256 || entry.size != file.size {
            bail!("network transfer file metadata does not match its manifest");
        }
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        bail!("network transfer hash must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_wire_peers(peers: &[String]) -> Result<()> {
    if peers.len() > 256 {
        bail!("network peer list is too large");
    }
    let mut unique = HashSet::new();
    for peer in peers {
        parse_endpoint_id(peer)?;
        if !unique.insert(peer) {
            bail!("network peer list contains duplicates");
        }
    }
    Ok(())
}

fn validate_path_list(paths: &[String]) -> Result<()> {
    if paths.len() > MAX_TRANSFER_FILES {
        bail!("network file request contains too many paths");
    }
    let mut unique = HashSet::new();
    for path in paths {
        validate_manifest_path(path)?;
        if !unique.insert(path) {
            bail!("network file request contains duplicate paths");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_file_payloads(files: &[FilePayload], manifest: &Manifest) -> Result<()> {
    if files.len() > MAX_TRANSFER_FILES {
        bail!("network transfer contains too many files");
    }
    let mut unique = HashSet::new();
    for file in files {
        validate_manifest_path(&file.path)?;
        if !unique.insert(&file.path) {
            bail!("network transfer contains duplicate file paths");
        }
        let entry = manifest
            .entries
            .get(&file.path)
            .ok_or_else(|| anyhow!("network file is not present in its manifest"))?;
        if entry.sha256 != file.sha256 {
            bail!("network file hash does not match its manifest");
        }
        let data = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        if URL_SAFE_NO_PAD.encode(&data) != file.content {
            bail!("network file payload must use canonical base64url encoding");
        }
        if data.len() as u64 != entry.size {
            bail!("network file payload has an invalid length");
        }
        let hash = hex::encode(Sha256::digest(&data));
        if hash != entry.sha256 {
            bail!("network file payload has an invalid hash");
        }
    }
    Ok(())
}

fn make_transfer_request(
    share: &Arc<ActiveShare>,
    local: &Manifest,
    remote: &Manifest,
) -> Result<(TransferRequest, usize)> {
    let mut download_paths = Vec::new();
    let mut download_resumes = Vec::new();
    for (path, remote_entry) in &remote.entries {
        let remote_record = ManifestRecordRef::File(remote_entry);
        if matches!(select_record(local.record(path), Some(remote_record)), Some(selected) if selected.version() == remote_record.version() && selected.is_tombstone() == remote_record.is_tombstone())
        {
            let local_content_matches = local.entries.get(path).is_some_and(|entry| {
                entry.size == remote_entry.size && entry.sha256 == remote_entry.sha256
            });
            if !local_content_matches {
                download_paths.push(path.clone());
                download_resumes.push(TransferFile {
                    path: path.clone(),
                    sha256: remote_entry.sha256.clone(),
                    size: remote_entry.size,
                    offset: partial_size(share, path, &remote_entry.sha256, remote_entry.size)?,
                });
            }
        }
    }
    download_paths.sort_unstable();
    download_paths.dedup();
    download_paths.truncate(MAX_TRANSFER_FILES);
    download_resumes.retain(|file| download_paths.binary_search(&file.path).is_ok());

    let mut upload_paths = Vec::new();
    for (path, local_entry) in &local.entries {
        let local_record = ManifestRecordRef::File(local_entry);
        let selected = select_record(Some(local_record), remote.record(path));
        let local_wins = matches!(selected, Some(winner) if winner.version() == local_record.version() && !winner.is_tombstone());
        let remote_content_matches = remote.entries.get(path).is_some_and(|entry| {
            entry.size == local_entry.size && entry.sha256 == local_entry.sha256
        });
        if local_wins && !remote_content_matches {
            upload_paths.push(path.clone());
        }
    }
    upload_paths.sort_unstable();
    let requested_uploads = upload_paths.len();
    upload_paths.truncate(MAX_TRANSFER_FILES);
    let uploads = upload_paths
        .iter()
        .filter_map(|path| {
            local.entries.get(path).map(|entry| TransferFile {
                path: path.clone(),
                sha256: entry.sha256.clone(),
                size: entry.size,
                offset: 0,
            })
        })
        .collect::<Vec<_>>();
    let pending_updates = requested_uploads.saturating_sub(uploads.len());
    Ok((
        TransferRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            download_paths,
            download_resumes,
            uploads,
        },
        pending_updates,
    ))
}

#[allow(dead_code)]
fn build_file_payloads(
    share: &Arc<ActiveShare>,
    manifest: &Manifest,
    paths: &[String],
) -> Result<Vec<FilePayload>> {
    validate_path_list(paths)?;
    let root = config_root(&share.config()?)?;
    let mut files = Vec::new();
    for path in paths {
        let Some(entry) = manifest.entries.get(path) else {
            continue;
        };
        let target = safe_local_path(&root, path, false)?;
        // Do not follow a leaf symlink. A stale manifest entry may otherwise cause a file outside
        // the shared directory to be uploaded after a local path was replaced with a symlink.
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            _ => continue,
        };
        if metadata.len() != entry.size {
            continue;
        }
        let bytes = fs::read(&target)
            .with_context(|| format!("unable to read shared file {}", target.display()))?;
        let after_read = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            _ => continue,
        };
        if after_read.len() != entry.size || bytes.len() as u64 != entry.size {
            continue;
        }
        if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            continue;
        }
        files.push(FilePayload {
            path: path.clone(),
            sha256: entry.sha256.clone(),
            content: URL_SAFE_NO_PAD.encode(bytes),
        });
    }
    Ok(files)
}

#[cfg(test)]
fn chunk_ranges(total: u64, offset: u64, chunk_size: usize) -> Vec<(u64, usize)> {
    let mut ranges = Vec::new();
    let mut current = offset.min(total);
    while current < total {
        let length = usize::try_from((total - current).min(chunk_size as u64))
            .expect("chunk length is bounded by the requested chunk size");
        ranges.push((current, length));
        current += length as u64;
    }
    ranges.push((current, 0));
    ranges
}

fn partial_path(share: &Arc<ActiveShare>, manifest_path: &str, sha256: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(manifest_path.as_bytes());
    hasher.update([0]);
    hasher.update(sha256.as_bytes());
    share
        .paths
        .share_tmp_dir(share.share_id)
        .join(format!("chunk-{}.part", hex::encode(hasher.finalize())))
}

fn partial_size(
    share: &Arc<ActiveShare>,
    manifest_path: &str,
    sha256: &str,
    size: u64,
) -> Result<u64> {
    let path = partial_path(share, manifest_path, sha256);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= size => Ok(metadata.len()),
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(&path).with_context(|| {
                format!(
                    "unable to remove oversized transfer partial {}",
                    path.display()
                )
            })?;
            Ok(0)
        }
        Ok(_) => bail!("transfer partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect transfer partial {}", path.display())),
    }
}

fn make_transfer_ready(
    share: &Arc<ActiveShare>,
    request: &TransferRequest,
    manifest: &Manifest,
) -> Result<TransferReady> {
    validate_transfer_files(&request.uploads, manifest)?;
    let uploads = request
        .uploads
        .iter()
        .map(|file| {
            Ok(TransferFile {
                path: file.path.clone(),
                sha256: file.sha256.clone(),
                size: file.size,
                offset: partial_size(share, &file.path, &file.sha256, file.size)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(TransferReady {
        protocol_version: PROTOCOL_VERSION,
        share_id: request.share_id,
        uploads,
    })
}

fn build_transfer_files(
    manifest: &Manifest,
    paths: &[String],
    resumes: &[TransferFile],
) -> Result<Vec<TransferFile>> {
    validate_path_list(paths)?;
    validate_transfer_file_shapes(resumes)?;
    let mut files = Vec::new();
    for path in paths {
        let Some(entry) = manifest.entries.get(path) else {
            continue;
        };
        let offset = resumes
            .iter()
            .find(|resume| {
                resume.path == *path && resume.sha256 == entry.sha256 && resume.size == entry.size
            })
            .map_or(0, |resume| resume.offset.min(entry.size));
        files.push(TransferFile {
            path: path.clone(),
            sha256: entry.sha256.clone(),
            size: entry.size,
            offset,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    Ok(files)
}

async fn send_upload_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    requested: &[TransferFile],
    ready: &[TransferFile],
    send: &mut SendStream,
) -> Result<()> {
    validate_transfer_file_shapes(requested)?;
    validate_transfer_file_shapes(ready)?;
    if requested.len() != ready.len() {
        bail!("upload resume list has an unexpected length");
    }
    for (request, resume) in requested.iter().zip(ready) {
        if request.path != resume.path
            || request.sha256 != resume.sha256
            || request.size != resume.size
        {
            bail!("upload resume metadata does not match the request");
        }
    }
    send_file_chunks_from_root(share, peer_endpoint_id, ready, send).await
}

async fn send_file_chunks_from_root(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    send: &mut SendStream,
) -> Result<()> {
    let root = config_root(&share.config()?)?;
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    let mut content = String::new();
    for file in files {
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "starting file upload"
        );
        let target = safe_local_path(&root, &file.path, false)?;
        let metadata = fs::symlink_metadata(&target)
            .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != file.size {
            bail!(
                "shared file changed before chunk transfer: {}",
                target.display()
            );
        }
        let mut source = tokio::fs::File::open(&target)
            .await
            .with_context(|| format!("unable to open shared file {}", target.display()))?;
        source
            .seek(std::io::SeekFrom::Start(file.offset))
            .await
            .with_context(|| format!("unable to seek shared file {}", target.display()))?;
        let mut offset = file.offset;
        while offset < file.size {
            let wanted = usize::try_from((file.size - offset).min(buffer.len() as u64))
                .context("transfer chunk size does not fit this platform")?;
            let count = source
                .read(&mut buffer[..wanted])
                .await
                .with_context(|| format!("unable to read shared file {}", target.display()))?;
            if count == 0 {
                bail!(
                    "shared file ended during chunk transfer: {}",
                    target.display()
                );
            }
            content.clear();
            URL_SAFE_NO_PAD.encode_string(&buffer[..count], &mut content);
            write_json_frame(
                send,
                &OutgoingChunkFrame {
                    path: &file.path,
                    sha256: &file.sha256,
                    offset,
                    content: &content,
                },
            )
            .await?;
            offset += count as u64;
        }
        let after = fs::symlink_metadata(&target)
            .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
        if !after.is_file() || after.len() != file.size {
            bail!(
                "shared file changed during chunk transfer: {}",
                target.display()
            );
        }
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "completed file upload"
        );
    }
    Ok(())
}

fn ensure_partial_file(path: &Path, offset: u64) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("unable to create transfer state {}", parent.display()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() == offset => {}
        Ok(metadata) if metadata.is_file() => {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("unable to open transfer partial {}", path.display()))?;
            file.set_len(offset)
                .with_context(|| format!("unable to resize transfer partial {}", path.display()))?;
        }
        Ok(_) => bail!("transfer partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = fs::File::create(path)
                .with_context(|| format!("unable to create transfer partial {}", path.display()))?;
            file.set_len(offset)
                .with_context(|| format!("unable to resize transfer partial {}", path.display()))?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("unable to inspect transfer partial {}", path.display()));
        }
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("unable to open transfer partial {}", path.display()))
}

fn verify_partial(path: &Path, file: &TransferFile) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect transfer partial {}", path.display()))?;
    if !metadata.is_file() || metadata.len() != file.size {
        bail!("transfer partial has an invalid size");
    }
    let mut source = fs::File::open(path)
        .with_context(|| format!("unable to open transfer partial {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .with_context(|| format!("unable to read transfer partial {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if hex::encode(hasher.finalize()) != file.sha256 {
        fs::remove_file(path).with_context(|| {
            format!(
                "transfer partial hash does not match its manifest for {}; unable to remove invalid transfer partial",
                file.path
            )
        })?;
        bail!(
            "transfer partial hash does not match its manifest for {}",
            file.path
        );
    }
    Ok(())
}

async fn receive_file_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    recv: &mut RecvStream,
) -> Result<Vec<CompletedFile>> {
    validate_transfer_file_shapes(files)?;
    let mut completed = Vec::new();
    let mut data = Vec::with_capacity(TRANSFER_CHUNK_BYTES);
    let mut canonical = String::new();
    for file in files {
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "starting file receive"
        );
        let partial = partial_path(share, &file.path, &file.sha256);
        let destination = ensure_partial_file(&partial, file.offset)
            .with_context(|| format!("unable to prepare transfer for {}", file.path))?;
        let mut destination = tokio::fs::File::from_std(destination);
        destination
            .seek(std::io::SeekFrom::Start(file.offset))
            .await
            .with_context(|| format!("unable to seek transfer partial {}", partial.display()))?;
        let mut offset = file.offset;
        while offset < file.size {
            let frame: ChunkFrame = read_json_frame(recv).await?;
            if frame.path != file.path || frame.sha256 != file.sha256 || frame.offset != offset {
                bail!("chunk frame does not match the requested transfer");
            }
            data.clear();
            URL_SAFE_NO_PAD
                .decode_vec(&frame.content, &mut data)
                .map_err(|_| anyhow!("chunk frame payload is not valid base64url"))?;
            canonical.clear();
            URL_SAFE_NO_PAD.encode_string(&data, &mut canonical);
            if canonical != frame.content
                || data.is_empty()
                || data.len() > TRANSFER_CHUNK_BYTES
                || offset.saturating_add(data.len() as u64) > file.size
            {
                bail!("chunk frame has an invalid payload length");
            }
            destination.write_all(&data).await.with_context(|| {
                format!("unable to write transfer partial {}", partial.display())
            })?;
            offset += data.len() as u64;
        }
        destination
            .sync_all()
            .await
            .with_context(|| format!("unable to flush transfer partial {}", partial.display()))?;
        drop(destination);
        run_blocking(|| verify_partial(&partial, file))?;
        completed.push(CompletedFile {
            file: file.clone(),
            staged_path: partial,
        });
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "completed file receive"
        );
    }
    Ok(completed)
}

async fn receive_download_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    recv: &mut RecvStream,
) -> Result<Vec<CompletedFile>> {
    receive_file_chunks(share, peer_endpoint_id, files, recv).await
}

async fn receive_upload_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    share_id: ShareId,
    requested: &[TransferFile],
    ready: &[TransferFile],
    recv: &mut RecvStream,
) -> Result<Vec<CompletedFile>> {
    validate_transfer_ready(
        &TransferReady {
            protocol_version: PROTOCOL_VERSION,
            share_id,
            uploads: ready.to_vec(),
        },
        share_id,
        requested,
    )?;
    receive_file_chunks(share, peer_endpoint_id, ready, recv).await
}

#[allow(dead_code)]
enum IncomingFile {
    Bytes(Vec<u8>),
    Staged(PathBuf),
}

struct CompletedFile {
    file: TransferFile,
    staged_path: PathBuf,
}

#[allow(dead_code)]
fn apply_remote_transfer(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    files: &[FilePayload],
) -> Result<ApplyOutcome> {
    remote.validate(share.share_id)?;
    validate_file_payloads(files, remote)?;
    let mut file_data = BTreeMap::new();
    for file in files {
        let bytes = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        file_data.insert(file.path.clone(), IncomingFile::Bytes(bytes));
    }
    apply_remote_transfer_impl(share, remote, &file_data)
}

fn apply_remote_staged_transfer(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    files: &[CompletedFile],
) -> Result<ApplyOutcome> {
    remote.validate(share.share_id)?;
    let descriptors = files
        .iter()
        .map(|file| file.file.clone())
        .collect::<Vec<_>>();
    validate_transfer_files(&descriptors, remote)?;
    let mut file_data = BTreeMap::new();
    for file in files {
        file_data.insert(
            file.file.path.clone(),
            IncomingFile::Staged(file.staged_path.clone()),
        );
    }
    let result = apply_remote_transfer_impl(share, remote, &file_data);
    if result.is_ok() {
        for file in files {
            let _ = fs::remove_file(&file.staged_path);
        }
    }
    result
}

fn apply_remote_transfer_impl(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    file_data: &BTreeMap<String, IncomingFile>,
) -> Result<ApplyOutcome> {
    let config = share.config()?;
    let root = config_root(&config)?;
    let local = share.paths.load_manifest(share.share_id)?;

    let mut candidate = local.clone();
    let mut pending_downloads = 0_usize;
    let mut applied_records = 0_usize;
    let mut all_paths = local
        .all_paths()
        .union(&remote.all_paths())
        .cloned()
        .collect::<Vec<_>>();
    all_paths.sort_by(|left, right| {
        manifest_path_depth(right)
            .cmp(&manifest_path_depth(left))
            .then_with(|| right.cmp(left))
    });
    for path in &all_paths {
        let local_record = local.record(path);
        let remote_record = remote.record(path);
        let selected_remote = remote_record_wins(local_record, remote_record);
        if !selected_remote {
            continue;
        }
        if let Some(ManifestRecordRef::Tombstone(tombstone)) = remote_record {
            remove_local_path(&root, path)?;
            candidate.entries.remove(path);
            candidate.directories.remove(path);
            candidate.symlinks.remove(path);
            candidate.tombstones.insert(path.clone(), tombstone.clone());
            applied_records = applied_records.saturating_add(1);
        }
    }

    all_paths.sort_unstable();
    let mut directory_permissions = Vec::new();
    for path in &all_paths {
        let local_record = local.record(path);
        let remote_record = remote.record(path);
        if !remote_record_wins(local_record, remote_record) {
            continue;
        }
        if let Some(ManifestRecordRef::Directory(entry)) = remote_record {
            ensure_local_directory(&root, path)?;
            candidate.entries.remove(path);
            candidate.symlinks.remove(path);
            candidate.tombstones.remove(path);
            candidate.directories.insert(path.clone(), entry.clone());
            directory_permissions.push((path.clone(), entry.permissions));
            applied_records = applied_records.saturating_add(1);
        }
    }

    for path in &all_paths {
        let local_record = local.record(path);
        let remote_record = remote.record(path);
        if !remote_record_wins(local_record, remote_record) {
            continue;
        }
        if let Some(ManifestRecordRef::Symlink(entry)) = remote_record {
            write_local_symlink(share, &root, path, &entry.target)?;
            candidate.entries.remove(path);
            candidate.directories.remove(path);
            candidate.tombstones.remove(path);
            candidate.symlinks.insert(path.clone(), entry.clone());
            applied_records = applied_records.saturating_add(1);
        }
    }

    for path in &all_paths {
        let local_record = local.record(path);
        let remote_record = remote.record(path);
        if !remote_record_wins(local_record, remote_record) {
            continue;
        }
        if let Some(ManifestRecordRef::File(entry)) = remote_record {
            if let Some(incoming) = file_data.get(path) {
                match incoming {
                    IncomingFile::Bytes(bytes) => {
                        write_local_file(share, &root, path, bytes, entry.permissions)?;
                    }
                    IncomingFile::Staged(staged_path) => {
                        write_local_staged_file(&root, path, staged_path, entry.permissions)?;
                    }
                }
                candidate.directories.remove(path);
                candidate.entries.remove(path);
                candidate.tombstones.remove(path);
                candidate.symlinks.remove(path);
                candidate.entries.insert(path.clone(), entry.clone());
                applied_records = applied_records.saturating_add(1);
            } else {
                // Metadata-only changes, including chmod, do not need to retransmit unchanged
                // content. Keep the manifest conservative if the local file disappeared after its
                // most recent scan.
                let local_content_matches = local.entries.get(path).is_some_and(|local_entry| {
                    local_entry.size == entry.size && local_entry.sha256 == entry.sha256
                });
                if local_content_matches
                    && local_file_matches_entry(&root, path, entry.size, &entry.sha256)?
                {
                    set_local_file_permissions(&root, path, entry.permissions)?;
                    candidate.directories.remove(path);
                    candidate.tombstones.remove(path);
                    candidate.entries.insert(path.clone(), entry.clone());
                    applied_records = applied_records.saturating_add(1);
                } else {
                    pending_downloads = pending_downloads.saturating_add(1);
                }
            }
        }
    }

    // Apply directory modes after their contents have been created. A remote directory can be
    // intentionally read-only, so applying it before the file phase could prevent the transfer.
    directory_permissions.sort_by(|(left, _), (right, _)| {
        manifest_path_depth(right)
            .cmp(&manifest_path_depth(left))
            .then_with(|| right.cmp(left))
    });
    for (path, permissions) in directory_permissions {
        set_local_directory_permissions(&root, &path, permissions)?;
    }
    candidate.scanned_at_ms = current_time_ms();
    candidate.validate(share.share_id)?;
    if candidate.entries != local.entries
        || candidate.directories != local.directories
        || candidate.symlinks != local.symlinks
        || candidate.tombstones != local.tombstones
    {
        observe_manifest_clock(share, &candidate)?;
        share.paths.save_manifest(&candidate)?;
    }
    debug!(
        share_id = %share.share_id,
        applied_records,
        pending_downloads,
        "remote transfer apply finished"
    );
    Ok(ApplyOutcome {
        pending_downloads,
        applied_records,
    })
}

fn remote_record_wins(
    local: Option<ManifestRecordRef<'_>>,
    remote: Option<ManifestRecordRef<'_>>,
) -> bool {
    match (local, remote) {
        (None, Some(_)) => true,
        (Some(local), Some(remote)) => {
            remote.version() > local.version()
                || (remote.version() == local.version()
                    && remote.is_tombstone()
                    && !local.is_tombstone())
        }
        _ => false,
    }
}

fn observe_manifest_clock(share: &Arc<ActiveShare>, manifest: &Manifest) -> Result<()> {
    let mut clock = share.paths.load_clock(share.share_id)?;
    let now_ms = current_time_ms();
    for entry in manifest.entries.values() {
        clock.observe(entry.version, now_ms)?;
    }
    for entry in manifest.directories.values() {
        clock.observe(entry.version, now_ms)?;
    }
    for tombstone in manifest.tombstones.values() {
        clock.observe(tombstone.version, now_ms)?;
    }
    share.paths.save_clock(share.share_id, &clock)
}

fn scan_and_save(share: &Arc<ActiveShare>, config: &ShareConfig) -> Result<()> {
    let root = config_root(config)?;
    let manifest = share.paths.load_manifest(share.share_id)?;
    let clock = share.paths.load_clock(share.share_id)?;
    let now_ms = current_time_ms();
    let scanned = scan_manifest(&root, &manifest, clock, &share.local_endpoint_id, now_ms)?;
    if scanned.changes > 0 {
        info!(
            share_id = %share.share_id,
            files = scanned.files,
            tombstones = scanned.tombstones,
            changes = scanned.changes,
            "local scan detected changes"
        );
    } else {
        debug!(share_id = %share.share_id, "local scan found no changes");
    }
    if scanned.changes > 0 {
        share.paths.save_clock(share.share_id, &scanned.clock)?;
    }
    if scanned.manifest_changed {
        share.paths.save_manifest(&scanned.manifest)?;
    }
    update_runtime(share, |status, _| {
        status.last_scan_at_ms = Some(now_ms);
        if scanned.changes > 0 {
            status.pending_updates = scanned.changes;
        }
    })?;
    Ok(())
}

fn merge_remote_peers<'a, I>(
    share: &Arc<ActiveShare>,
    peers: I,
    authenticated_peer: Option<EndpointId>,
) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut known = share.paths.load_known_peers(share.share_id)?;
    let mut endpoint_ids = Vec::new();
    for peer in peers {
        let endpoint_id = parse_endpoint_id(peer)?;
        if endpoint_id != share.local_endpoint_id {
            endpoint_ids.push(endpoint_id);
        }
    }
    if let Some(peer) = authenticated_peer.filter(|peer| *peer != share.local_endpoint_id) {
        endpoint_ids.push(peer);
    }
    known.merge_endpoint_ids(endpoint_ids, current_time_ms());
    share.paths.save_known_peers(share.share_id, &known)
}

fn known_peer_strings(share: &Arc<ActiveShare>, remote: &EndpointId) -> Result<Vec<String>> {
    let peers = share.paths.load_known_peers(share.share_id)?;
    let mut values = peers
        .peers
        .iter()
        .filter_map(|peer| {
            parse_endpoint_id(&peer.endpoint_id)
                .ok()
                .filter(|endpoint_id| {
                    endpoint_id != &share.local_endpoint_id && endpoint_id != remote
                })
                .map(|_| peer.endpoint_id.clone())
        })
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values.truncate(256);
    Ok(values)
}

fn config_root(config: &ShareConfig) -> Result<PathBuf> {
    let root = PathBuf::from(&config.local_directory);
    let metadata = fs::metadata(&root)
        .with_context(|| format!("unable to inspect local directory {}", root.display()))?;
    if !metadata.is_dir() {
        bail!(
            "registered local path {} is not a directory",
            root.display()
        );
    }
    fs::canonicalize(&root)
        .with_context(|| format!("unable to normalize local directory {}", root.display()))
}

fn safe_local_path(root: &Path, manifest_path: &str, writing: bool) -> Result<PathBuf> {
    let target = path_for_manifest(root, manifest_path)?;
    let mut parent = root.to_path_buf();
    let components = manifest_path.split('/').collect::<Vec<_>>();
    for component in &components[..components.len().saturating_sub(1)] {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("shared path contains a symbolic link: {}", parent.display())
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "shared path parent is not a directory: {}",
                    parent.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && writing => {
                fs::create_dir(&parent).with_context(|| {
                    format!("unable to create shared directory {}", parent.display())
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("unable to inspect {}", parent.display()));
            }
        }
    }
    Ok(target)
}

fn manifest_path_depth(path: &str) -> usize {
    path.bytes().filter(|byte| *byte == b'/').count() + 1
}

fn ensure_local_directory(root: &Path, manifest_path: &str) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            // A newer remote directory record may replace a local file at the same path. Do not
            // follow a symbolic link or replace another special file type.
            Ok(metadata) if metadata.is_file() => fs::remove_file(&target)
                .with_context(|| format!("unable to replace shared file {}", target.display()))?,
            Ok(_) => bail!("refusing to replace non-directory {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared directory {}", target.display())
                });
            }
        }
        fs::create_dir(&target)
            .with_context(|| format!("unable to create shared directory {}", target.display()))
    })
}

fn local_file_matches_entry(
    root: &Path,
    manifest_path: &str,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<bool> {
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("refusing to use symbolic link {}", target.display())
            }
            Ok(metadata) if metadata.is_file() && metadata.len() == expected_size => metadata,
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared file {}", target.display())
                });
            }
        };
        let before_modified = metadata.modified().ok();
        with_readable_file(&target, || {
            let mut file = fs::File::open(&target)
                .with_context(|| format!("unable to read shared file {}", target.display()))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let count = file
                    .read(&mut buffer)
                    .with_context(|| format!("unable to read shared file {}", target.display()))?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            let after = file
                .metadata()
                .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
            Ok(after.is_file()
                && after.len() == expected_size
                && after.modified().ok() == before_modified
                && hex::encode(hasher.finalize()) == expected_sha256)
        })
    })
}

fn write_local_file(
    share: &Arc<ActiveShare>,
    root: &Path,
    manifest_path: &str,
    bytes: &[u8],
    permissions: Option<u16>,
) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            // Descendant tombstones are applied before files, so a newer remote file can replace
            // an emptied local directory without discarding untracked content.
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!("unable to replace shared directory {}", target.display())
            })?,
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => bail!("refusing to replace non-file {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared file {}", target.display())
                });
            }
        }
        // Transfer staging belongs in the registered share state directory, never in the synced tree.
        let temp = share.paths.share_tmp_dir(share.share_id).join(format!(
            "transfer-{}-{}.tmp",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        let result = (|| -> Result<()> {
            fs::write(&temp, bytes)
                .with_context(|| format!("unable to stage downloaded file {}", temp.display()))?;
            match fs::rename(&temp, &target) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                    // Application data and the shared directory may live on separate volumes. Fall
                    // back to a direct replacement rather than creating a program temporary file in
                    // the shared tree.
                    write_cross_device_target(&target, bytes, permissions)?;
                    fs::remove_file(&temp).with_context(|| {
                        format!("unable to remove transfer staging file {}", temp.display())
                    })?;
                    Ok(())
                }
                Err(_) if cfg!(windows) && target.exists() => {
                    // Windows rename does not consistently replace an existing file across supported
                    // filesystems. The target has already been checked not to be a symlink or directory.
                    fs::remove_file(&target).with_context(|| {
                        format!("unable to replace downloaded file {}", target.display())
                    })?;
                    fs::rename(&temp, &target).with_context(|| {
                        format!("unable to install downloaded file {}", target.display())
                    })
                }
                Err(error) => Err(error).with_context(|| {
                    format!("unable to install downloaded file {}", target.display())
                }),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result?;
        set_local_file_permissions(root, manifest_path, permissions)
    })
}

fn write_local_staged_file(
    root: &Path,
    manifest_path: &str,
    staged_path: &Path,
    permissions: Option<u16>,
) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!("unable to replace shared directory {}", target.display())
            })?,
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => bail!("refusing to replace non-file {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared path {}", target.display())
                });
            }
        }
        let staged_metadata = fs::symlink_metadata(staged_path)
            .with_context(|| format!("unable to inspect staged file {}", staged_path.display()))?;
        if !staged_metadata.is_file() || staged_metadata.file_type().is_symlink() {
            bail!("staged transfer is not a regular file");
        }
        match fs::rename(staged_path, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                with_writable_cross_device_target(&target, permissions, || {
                    fs::copy(staged_path, &target).map(|_| ()).with_context(|| {
                        format!("unable to install staged file {}", target.display())
                    })
                })?;
                fs::remove_file(staged_path).with_context(|| {
                    format!("unable to remove staged file {}", staged_path.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to install staged file {}", target.display())
                });
            }
        }
        set_local_file_permissions(root, manifest_path, permissions)
    })
}

fn write_local_symlink(
    share: &Arc<ActiveShare>,
    root: &Path,
    manifest_path: &str,
    target: &str,
) -> Result<()> {
    validate_manifest_path(manifest_path)?;
    if target.is_empty() || target.len() > 4096 || target.contains('\0') {
        bail!("remote symlink target is invalid");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        with_writable_parents(root, manifest_path, true, || {
            let local_target = safe_local_path(root, manifest_path, true)?;
            match fs::symlink_metadata(&local_target) {
                Ok(metadata) if metadata.is_dir() => {
                    fs::remove_dir(&local_target).with_context(|| {
                        format!(
                            "unable to replace shared directory {}",
                            local_target.display()
                        )
                    })?;
                }
                Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                    fs::remove_file(&local_target).with_context(|| {
                        format!("unable to replace shared path {}", local_target.display())
                    })?;
                }
                Ok(_) => bail!("refusing to replace non-file {}", local_target.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("unable to inspect shared path {}", local_target.display())
                    });
                }
            }
            let temporary = share.paths.share_tmp_dir(share.share_id).join(format!(
                "symlink-{}-{}.tmp",
                std::process::id(),
                rand::rng().random::<u64>()
            ));
            let result = (|| -> Result<()> {
                symlink(target, &temporary)
                    .with_context(|| format!("unable to stage symlink target {target}"))?;
                match fs::rename(&temporary, &local_target) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                        let _ = fs::remove_file(&temporary);
                        symlink(target, &local_target).with_context(|| {
                            format!("unable to install symlink {}", local_target.display())
                        })
                    }
                    Err(error) => Err(error).with_context(|| {
                        format!("unable to install symlink {}", local_target.display())
                    }),
                }
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (share, root, manifest_path, target);
        bail!("symbolic links are not supported on this platform")
    }
}

fn remove_local_path(root: &Path, manifest_path: &str) -> Result<()> {
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(&target)
                    .with_context(|| format!("unable to remove shared path {}", target.display()))
            }
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!(
                    "unable to remove empty shared directory {}",
                    target.display()
                )
            }),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("unable to inspect {}", target.display()))
            }
        }
    })
}

fn set_local_file_permissions(
    root: &Path,
    manifest_path: &str,
    permissions: Option<u16>,
) -> Result<()> {
    let Some(permissions) = permissions else {
        return Ok(());
    };
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        set_permissions(&target, permissions, false)
    })
}

fn set_local_directory_permissions(
    root: &Path,
    manifest_path: &str,
    permissions: Option<u16>,
) -> Result<()> {
    let Some(permissions) = permissions else {
        return Ok(());
    };
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        set_permissions(&target, permissions, true)
    })
}

#[cfg(unix)]
struct PermissionRestore {
    path: PathBuf,
    permissions: u32,
}

#[cfg(unix)]
fn with_writable_parents<T>(
    root: &Path,
    manifest_path: &str,
    create_missing_parents: bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    validate_manifest_path(manifest_path)?;
    let mut restores = Vec::new();
    let preparation = (|| -> Result<()> {
        prepare_directory_for_write(root, true, &mut restores)?;
        let components = manifest_path.split('/').collect::<Vec<_>>();
        let mut parent = root.to_path_buf();
        for component in &components[..components.len().saturating_sub(1)] {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!("shared path contains a symbolic link: {}", parent.display())
                }
                Ok(metadata) if !metadata.is_dir() => {
                    bail!(
                        "shared path parent is not a directory: {}",
                        parent.display()
                    )
                }
                Ok(_) => prepare_directory_for_write(&parent, true, &mut restores)?,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && create_missing_parents =>
                {
                    fs::create_dir(&parent).with_context(|| {
                        format!("unable to create shared directory {}", parent.display())
                    })?;
                    prepare_directory_for_write(&parent, false, &mut restores)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("unable to inspect {}", parent.display()));
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = preparation {
        let _ = restore_parent_permissions(restores);
        return Err(error);
    }
    let result = operation();
    let restore_result = restore_parent_permissions(restores);
    match (result, restore_result) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(unix)]
fn restore_parent_permissions(restores: Vec<PermissionRestore>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    restores.into_iter().rev().try_for_each(|restore| {
        fs::set_permissions(
            &restore.path,
            fs::Permissions::from_mode(restore.permissions),
        )
        .with_context(|| {
            format!(
                "unable to restore permissions on shared directory {}",
                restore.path.display()
            )
        })
    })
}

#[cfg(unix)]
fn prepare_directory_for_write(
    path: &Path,
    restore_existing_permissions: bool,
    restores: &mut Vec<PermissionRestore>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect shared directory {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("shared path contains a symbolic link: {}", path.display());
    }
    if !metadata.is_dir() {
        bail!("shared path parent is not a directory: {}", path.display());
    }
    let permissions = metadata.permissions().mode() & 0o7777;
    if permissions & 0o300 == 0o300 {
        return Ok(());
    }
    match fs::set_permissions(path, fs::Permissions::from_mode(permissions | 0o300)) {
        Ok(()) => {
            if restore_existing_permissions {
                restores.push(PermissionRestore {
                    path: path.to_path_buf(),
                    permissions,
                });
            }
        }
        Err(_error) if directory_mode_allows_non_owner_writes(permissions) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "unable to make shared directory writable {}",
                    path.display()
                )
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn directory_mode_allows_non_owner_writes(permissions: u32) -> bool {
    [0o030, 0o003]
        .into_iter()
        .any(|required| permissions & required == required)
}

#[cfg(not(unix))]
fn with_writable_parents<T>(
    _root: &Path,
    _manifest_path: &str,
    _create_missing_parents: bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

#[cfg(unix)]
fn with_readable_file<T>(target: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(target)
        .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to read symbolic link {}", target.display());
    }
    if !metadata.is_file() {
        bail!("shared path is not a regular file: {}", target.display());
    }
    let permissions = metadata.permissions().mode() & 0o7777;
    let restore_permissions = if permissions & 0o400 == 0 {
        match fs::set_permissions(target, fs::Permissions::from_mode(permissions | 0o400)) {
            Ok(()) => Some(permissions),
            Err(_) if permissions & 0o044 != 0 => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to make shared file readable {}", target.display())
                });
            }
        }
    } else {
        None
    };
    let result = operation();
    let restore_result = restore_permissions.map_or_else(
        || Ok(()),
        |permissions| {
            fs::set_permissions(target, fs::Permissions::from_mode(permissions)).with_context(
                || {
                    format!(
                        "unable to restore permissions on shared file {}",
                        target.display()
                    )
                },
            )
        },
    );
    match (result, restore_result) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(not(unix))]
fn with_readable_file<T>(_target: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    operation()
}

#[cfg(unix)]
fn set_permissions(target: &Path, permissions: u16, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(target)
        .with_context(|| format!("unable to inspect shared path {}", target.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to change permissions on symbolic link {}",
            target.display()
        );
    }
    if directory != metadata.is_dir() || (!directory && !metadata.is_file()) {
        bail!("shared path has an unexpected type: {}", target.display());
    }
    fs::set_permissions(target, fs::Permissions::from_mode(u32::from(permissions)))
        .with_context(|| format!("unable to set permissions on {}", target.display()))
}

#[cfg(not(unix))]
fn set_permissions(_target: &Path, _permissions: u16, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn with_writable_cross_device_target<T>(
    target: &Path,
    final_permissions: Option<u16>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::os::unix::fs::PermissionsExt as _;

    let restore_permissions = match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to replace symbolic link {}", target.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("refusing to replace non-file {}", target.display())
        }
        Ok(metadata) => {
            let permissions = metadata.permissions().mode() & 0o7777;
            if permissions & 0o200 == 0 {
                match fs::set_permissions(target, fs::Permissions::from_mode(permissions | 0o200)) {
                    Ok(()) => Some(permissions),
                    Err(_) if permissions & 0o022 != 0 => None,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("unable to make shared file writable {}", target.display())
                        });
                    }
                }
            } else {
                None
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("unable to inspect shared file {}", target.display()));
        }
    };
    let operation_result = operation();
    if (operation_result.is_err() || final_permissions.is_none())
        && let Some(permissions) = restore_permissions
    {
        fs::set_permissions(target, fs::Permissions::from_mode(permissions)).with_context(
            || {
                format!(
                    "unable to restore permissions on shared file {}",
                    target.display()
                )
            },
        )?;
    }
    operation_result
}

#[cfg(not(unix))]
fn with_writable_cross_device_target<T>(
    _target: &Path,
    _final_permissions: Option<u16>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

fn write_cross_device_target(
    target: &Path,
    bytes: &[u8],
    final_permissions: Option<u16>,
) -> Result<()> {
    with_writable_cross_device_target(target, final_permissions, || {
        fs::write(target, bytes)
            .with_context(|| format!("unable to install downloaded file {}", target.display()))
    })
}

fn update_runtime<F>(share: &Arc<ActiveShare>, update: F) -> Result<()>
where
    F: FnOnce(&mut RuntimeStatus, u64),
{
    let _status_lock = share
        .status_lock
        .lock()
        .map_err(|_| anyhow!("runtime status lock was poisoned"))?;
    let now_ms = current_time_ms();
    let mut status = share
        .paths
        .load_runtime_status(share.share_id)?
        .unwrap_or_else(|| RuntimeStatus::stopped(now_ms));
    if status.process_id == 0 {
        status.process_id = std::process::id();
        status.started_at_ms = now_ms;
    }
    status.heartbeat_at_ms = now_ms;
    update(&mut status, now_ms);
    share.paths.save_runtime_status(share.share_id, &status)
}

fn set_runtime_state(
    share: &Arc<ActiveShare>,
    state: RuntimeState,
    health: SyncHealth,
    error: Option<&str>,
) -> Result<()> {
    update_runtime(share, |status, _| {
        status.state = state;
        status.health = health;
        status.connected_peers = 0;
        status.last_error = error.map(str::to_owned);
    })
}

fn set_runtime_error(share: &Arc<ActiveShare>, message: &str) -> Result<()> {
    update_runtime(share, |status, _| {
        status.state = RuntimeState::Degraded;
        status.health = SyncHealth::Offline;
        status.connected_peers = 0;
        status.last_error = Some(message.to_owned());
    })
}

fn refresh_heartbeat(share: &Arc<ActiveShare>) -> Result<()> {
    update_runtime(share, |_, _| {})
}

fn set_stopped(share: &Arc<ActiveShare>) -> Result<()> {
    update_runtime(share, |status, _| {
        status.process_id = 0;
        status.state = RuntimeState::Stopped;
        status.connected_peers = 0;
    })
}

fn make_client_hello(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    nonce: [u8; 32],
) -> [u8; CLIENT_HELLO_LENGTH] {
    let mut output = [0_u8; CLIENT_HELLO_LENGTH];
    let mut cursor = 0_usize;
    put(&mut output, &mut cursor, &AUTH_MAGIC);
    put(&mut output, &mut cursor, &PROTOCOL_VERSION.to_be_bytes());
    put(&mut output, &mut cursor, config.share_id.as_bytes());
    put(&mut output, &mut cursor, client.as_bytes());
    put(&mut output, &mut cursor, &nonce);
    let proof = client_proof(config, client, server, nonce);
    put(&mut output, &mut cursor, &proof);
    output
}

fn make_server_hello(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> [u8; SERVER_HELLO_LENGTH] {
    let mut output = [0_u8; SERVER_HELLO_LENGTH];
    let mut cursor = 0_usize;
    put(&mut output, &mut cursor, &AUTH_MAGIC);
    put(&mut output, &mut cursor, &PROTOCOL_VERSION.to_be_bytes());
    put(&mut output, &mut cursor, config.share_id.as_bytes());
    put(&mut output, &mut cursor, server.as_bytes());
    put(&mut output, &mut cursor, &client_nonce);
    put(&mut output, &mut cursor, &server_nonce);
    let proof = server_proof(config, client, server, client_nonce, server_nonce);
    put(&mut output, &mut cursor, &proof);
    output
}

struct ClientHello {
    share_id: ShareId,
    client_id: EndpointId,
    nonce: [u8; 32],
    proof: [u8; 32],
}

struct ServerHello {
    share_id: ShareId,
    server_id: EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    proof: [u8; 32],
}

async fn read_client_hello(recv: &mut RecvStream) -> Result<ClientHello> {
    let mut bytes = [0_u8; CLIENT_HELLO_LENGTH];
    recv.read_exact(&mut bytes)
        .await
        .context("unable to read sync authentication")?;
    let mut cursor = 0_usize;
    if take::<4>(&bytes, &mut cursor)? != AUTH_MAGIC {
        bail!("invalid sync authentication magic");
    }
    if u16::from_be_bytes(take(&bytes, &mut cursor)?) != PROTOCOL_VERSION {
        bail!("unsupported sync protocol version");
    }
    let share_id = ShareId(take(&bytes, &mut cursor)?);
    let client_bytes: [u8; 32] = take(&bytes, &mut cursor)?;
    let client_id = EndpointId::from_bytes(&client_bytes)
        .map_err(|_| anyhow!("invalid sync client endpoint ID"))?;
    let nonce = take(&bytes, &mut cursor)?;
    let proof = take(&bytes, &mut cursor)?;
    Ok(ClientHello {
        share_id,
        client_id,
        nonce,
        proof,
    })
}

async fn read_server_hello(recv: &mut RecvStream) -> Result<ServerHello> {
    let mut bytes = [0_u8; SERVER_HELLO_LENGTH];
    recv.read_exact(&mut bytes)
        .await
        .context("unable to read sync authentication")?;
    let mut cursor = 0_usize;
    if take::<4>(&bytes, &mut cursor)? != AUTH_MAGIC {
        bail!("invalid sync authentication magic");
    }
    if u16::from_be_bytes(take(&bytes, &mut cursor)?) != PROTOCOL_VERSION {
        bail!("unsupported sync protocol version");
    }
    let share_id = ShareId(take(&bytes, &mut cursor)?);
    let server_bytes: [u8; 32] = take(&bytes, &mut cursor)?;
    let server_id = EndpointId::from_bytes(&server_bytes)
        .map_err(|_| anyhow!("invalid sync server endpoint ID"))?;
    let client_nonce = take(&bytes, &mut cursor)?;
    let server_nonce = take(&bytes, &mut cursor)?;
    let proof = take(&bytes, &mut cursor)?;
    Ok(ServerHello {
        share_id,
        server_id,
        client_nonce,
        server_nonce,
        proof,
    })
}

fn validate_client_hello(
    hello: &ClientHello,
    config: &ShareConfig,
    transport_client: &EndpointId,
    server: &EndpointId,
) -> Result<()> {
    if hello.share_id != config.share_id || hello.client_id != *transport_client {
        bail!("sync client authentication is not bound to its transport identity");
    }
    let expected = client_proof(config, &hello.client_id, server, hello.nonce);
    if expected.ct_eq(&hello.proof).unwrap_u8() != 1 {
        bail!("sync client authentication failed");
    }
    Ok(())
}

fn validate_server_hello(
    hello: &ServerHello,
    config: &ShareConfig,
    client: &EndpointId,
    transport_server: &EndpointId,
    expected_client_nonce: [u8; 32],
) -> Result<()> {
    if hello.share_id != config.share_id
        || hello.server_id != *transport_server
        || hello.client_nonce != expected_client_nonce
    {
        bail!("sync server authentication is not bound to its transport identity");
    }
    let expected = server_proof(
        config,
        client,
        &hello.server_id,
        hello.client_nonce,
        hello.server_nonce,
    );
    if expected.ct_eq(&hello.proof).unwrap_u8() != 1 {
        bail!("sync server authentication failed");
    }
    Ok(())
}

fn client_proof(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    nonce: [u8; 32],
) -> [u8; 32] {
    proof(config, b"client", client, server, &[nonce.as_slice()])
}

fn server_proof(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> [u8; 32] {
    proof(
        config,
        b"server",
        client,
        server,
        &[client_nonce.as_slice(), server_nonce.as_slice()],
    )
}

fn proof(
    config: &ShareConfig,
    role: &[u8],
    client: &EndpointId,
    server: &EndpointId,
    nonces: &[&[u8]],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(config.share_secret.as_bytes())
        .expect("HMAC accepts a fixed-size key");
    mac.update(b"syncbox/auth/v1");
    mac.update(role);
    mac.update(config.share_id.as_bytes());
    mac.update(client.as_bytes());
    mac.update(server.as_bytes());
    for nonce in nonces {
        mac.update(nonce);
    }
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn put<const N: usize>(target: &mut [u8], cursor: &mut usize, value: &[u8; N]) {
    target[*cursor..*cursor + N].copy_from_slice(value);
    *cursor += N;
}

fn take<const N: usize>(source: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| anyhow!("sync authentication length overflow"))?;
    let bytes = source
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("sync authentication is truncated"))?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| anyhow!("sync authentication has an invalid length"))
}

async fn write_json_frame<T: Serialize + Sync>(send: &mut SendStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value).context("unable to serialize sync protocol message")?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        bail!("sync protocol message exceeds its maximum size");
    }
    let length: u32 = payload
        .len()
        .try_into()
        .map_err(|_| anyhow!("sync protocol message is too large"))?;
    send.write_all(&length.to_be_bytes())
        .await
        .context("unable to write sync protocol frame length")?;
    send.write_all(&payload)
        .await
        .context("unable to write sync protocol frame")?;
    Ok(())
}

async fn read_json_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut length_bytes = [0_u8; 4];
    recv.read_exact(&mut length_bytes)
        .await
        .context("unable to read sync protocol frame length")?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| anyhow!("sync protocol frame length overflow"))?;
    if length > MAX_CONTROL_FRAME_BYTES {
        bail!("sync protocol frame exceeds its maximum size");
    }
    let mut bytes = vec![0_u8; length];
    recv.read_exact(&mut bytes)
        .await
        .context("unable to read sync protocol frame")?;
    serde_json::from_slice(&bytes).context("unable to parse sync protocol frame")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(unix)]
    use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

    use iroh::{
        SecretKey, TransportAddr,
        address_lookup::{AddrFilter, EndpointData},
    };
    #[cfg(unix)]
    use tempfile::TempDir;

    use super::*;
    use crate::types::{FORMAT_VERSION, ShareSecret};
    #[cfg(unix)]
    use crate::{
        manifest::{
            DirectoryEntry, MANIFEST_FORMAT_VERSION, ManifestEntry, SymlinkEntry, Tombstone,
        },
        types::{ClockState, HlcTimestamp, KnownPeers, RuntimeStatus},
    };

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_falls_back_without_panicking() {
        assert_eq!(run_blocking(|| 42), 42);
    }

    #[test]
    fn unfiltered_pkarr_candidates_keep_direct_addresses() {
        let data = EndpointData::from_iter([
            TransportAddr::Ip("192.0.2.1:443".parse().unwrap()),
            TransportAddr::Relay("https://relay.example.com".parse().unwrap()),
        ]);
        assert_eq!(
            data.apply_filter(&AddrFilter::unfiltered()).addrs().count(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn incoming_handlers_are_drained_before_shutdown() {
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut handlers = tokio::task::JoinSet::new();
        handlers.spawn(async move {
            let _ = release_rx.await;
        });

        let mut drain = Box::pin(drain_incoming_handlers(&mut handlers));
        assert!(
            timeout(Duration::from_millis(10), &mut drain)
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        drain.await;
        assert!(handlers.is_empty());
    }

    fn config() -> (ShareConfig, EndpointId, EndpointId) {
        let client = SecretKey::from_bytes(&[1; 32]).public();
        let server = SecretKey::from_bytes(&[2; 32]).public();
        (
            ShareConfig {
                format_version: FORMAT_VERSION,
                share_id: ShareId([3; 32]),
                share_secret: ShareSecret::from_bytes([4; 32]),
                name: "test".to_owned(),
                local_directory: "/tmp/test".to_owned(),
                created_at_ms: 0,
                initial_peers: vec![server.to_string()],
                initial_sync_complete: true,
            },
            client,
            server,
        )
    }

    #[test]
    fn authentication_proof_is_bound_to_each_share() {
        let (config, client, server) = config();
        let proof = client_proof(&config, &client, &server, [7; 32]);
        let mut other = config;
        other.share_id = ShareId([8; 32]);
        assert_ne!(proof, client_proof(&other, &client, &server, [7; 32]));
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

    #[cfg(unix)]
    #[test]
    fn transfer_request_reuses_authenticated_manifest() {
        let share_id = ShareId([40; 32]);
        let endpoint = SecretKey::from_bytes(&[41; 32]).public();
        let bytes = b"payload";
        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "file.txt".to_owned(),
                file_entry(bytes, 0o640, timestamp(1, endpoint)),
            )]),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let request = TransferRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id,
            download_paths: Vec::new(),
            download_resumes: Vec::new(),
            uploads: vec![TransferFile {
                path: "file.txt".to_owned(),
                sha256: manifest.entries["file.txt"].sha256.clone(),
                size: bytes.len() as u64,
                offset: 0,
            }],
        };
        let encoded = serde_json::to_value(&request).unwrap();

        assert!(encoded.get("manifest").is_none());
        validate_transfer_request(&request, share_id, &manifest).unwrap();
        assert!(
            validate_transfer_request(&request, share_id, &Manifest::empty(share_id, 2)).is_err()
        );
    }

    #[test]
    fn chunk_ranges_resume_from_existing_offset() {
        assert_eq!(chunk_ranges(10, 4, 3), vec![(4, 3), (7, 3), (10, 0)]);
    }

    #[cfg(unix)]
    #[test]
    fn transfer_descriptors_accept_files_larger_than_sixteen_mib() {
        let bytes = vec![7_u8; 17 * 1024 * 1024];
        let share_id = ShareId([23; 32]);
        let endpoint = SecretKey::from_bytes(&[24; 32]).public();
        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "large.bin".to_owned(),
                file_entry(&bytes, 0o640, timestamp(1, endpoint)),
            )]),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let file = TransferFile {
            path: "large.bin".to_owned(),
            sha256: manifest.entries["large.bin"].sha256.clone(),
            size: bytes.len() as u64,
            offset: 0,
        };
        validate_transfer_files(&[file], &manifest).unwrap();
    }

    #[cfg(unix)]
    #[allow(clippy::needless_pass_by_value)]
    fn active_share(root: &Path, manifest: Manifest, endpoint: EndpointId) -> Arc<ActiveShare> {
        let paths = DataPaths::from_root(root.parent().unwrap().join("state"));
        let config = ShareConfig {
            format_version: FORMAT_VERSION,
            share_id: manifest.share_id,
            share_secret: ShareSecret::from_bytes([9; 32]),
            name: "test".to_owned(),
            local_directory: root.to_string_lossy().into_owned(),
            created_at_ms: 0,
            initial_peers: Vec::new(),
            initial_sync_complete: true,
        };
        paths
            .create_share_state(
                &config,
                &manifest,
                &ClockState::new(),
                &KnownPeers::empty(),
                &RuntimeStatus::stopped(0),
            )
            .unwrap();
        Arc::new(ActiveShare {
            paths,
            share_id: manifest.share_id,
            config: Arc::new(RwLock::new(config)),
            receive_lock: Arc::new(Mutex::new(())),
            operation_lock: Arc::new(Mutex::new(())),
            status_lock: Arc::new(std::sync::Mutex::new(())),
            local_endpoint_id: endpoint,
        })
    }

    #[cfg(unix)]
    fn timestamp(wall_ms: u64, endpoint: EndpointId) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms,
            counter: 0,
            author: *endpoint.as_bytes(),
        }
    }

    #[cfg(unix)]
    fn file_entry(bytes: &[u8], permissions: u16, version: HlcTimestamp) -> ManifestEntry {
        ManifestEntry {
            size: bytes.len() as u64,
            modified_at_ns: 0,
            sha256: hex::encode(Sha256::digest(bytes)),
            permissions: Some(permissions),
            version,
        }
    }

    #[cfg(unix)]
    fn directory_entry(permissions: u16, version: HlcTimestamp) -> DirectoryEntry {
        DirectoryEntry {
            permissions: Some(permissions),
            version,
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u16 {
        (fs::metadata(path).unwrap().permissions().mode() & 0o7777) as u16
    }

    #[cfg(unix)]
    #[test]
    fn valid_transfer_partial_resumes_and_survives_verification() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();
        let share_id = ShareId([30; 32]);
        let endpoint = SecretKey::from_bytes(&[31; 32]).public();
        let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
        let bytes = b"valid data";
        let file = TransferFile {
            path: "file.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            offset: 0,
        };
        let partial = partial_path(&share, &file.path, &file.sha256);
        fs::write(&partial, &bytes[..5]).unwrap();

        assert_eq!(
            partial_size(&share, &file.path, &file.sha256, file.size).unwrap(),
            5
        );
        fs::write(&partial, bytes).unwrap();
        verify_partial(&partial, &file).unwrap();
        assert!(partial.exists());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_transfer_partial_is_removed_after_hash_mismatch() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();
        let share_id = ShareId([32; 32]);
        let endpoint = SecretKey::from_bytes(&[33; 32]).public();
        let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
        let bytes = b"valid data";
        let file = TransferFile {
            path: "file.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            offset: 0,
        };
        let partial = partial_path(&share, &file.path, &file.sha256);
        fs::write(&partial, b"corrupt!!!").unwrap();

        let error = verify_partial(&partial, &file).unwrap_err();

        assert!(format!("{error:#}").contains("file.txt"));
        assert!(!partial.exists());
        assert_eq!(
            partial_size(&share, &file.path, &file.sha256, file.size).unwrap(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn cross_device_copy_temporarily_makes_read_only_target_writable() {
        let temporary = TempDir::new().unwrap();
        let target = temporary.path().join("target.txt");
        let staged = temporary.path().join("staged.part");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();

        with_writable_cross_device_target(&target, None, || {
            fs::copy(&staged, &target)
                .map(|_| ())
                .context("simulated cross-device copy failed")
        })
        .unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(mode(&target), 0o444);
        assert!(staged.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cross_device_copy_restores_permissions_after_failure() {
        let temporary = TempDir::new().unwrap();
        let target = temporary.path().join("target.txt");
        let staged = temporary.path().join("staged.part");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();

        let error = with_writable_cross_device_target(&target, None, || {
            Err::<(), _>(anyhow!("simulated cross-device copy failure"))
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("simulated cross-device copy failure"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(mode(&target), 0o444);
        assert!(staged.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remote_transfer_applies_file_and_directory_permissions() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();
        let share_id = ShareId([10; 32]);
        let local_endpoint = SecretKey::from_bytes(&[11; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[12; 32]).public();
        let share = active_share(&root, Manifest::empty(share_id, 0), local_endpoint);
        let bytes = b"secret";
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::from([(
                "private/config.txt".to_owned(),
                file_entry(bytes, 0o640, timestamp(2, remote_endpoint)),
            )]),
            directories: BTreeMap::from([
                (
                    "empty".to_owned(),
                    directory_entry(0o710, timestamp(1, remote_endpoint)),
                ),
                (
                    "private".to_owned(),
                    directory_entry(0o750, timestamp(1, remote_endpoint)),
                ),
            ]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let files = vec![FilePayload {
            path: "private/config.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            content: URL_SAFE_NO_PAD.encode(bytes),
        }];

        let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();
        assert_eq!(outcome.pending_downloads, 0);
        assert_eq!(fs::read(root.join("private/config.txt")).unwrap(), bytes);
        assert_eq!(mode(&root.join("private/config.txt")), 0o640);
        assert_eq!(mode(&root.join("private")), 0o750);
        assert_eq!(mode(&root.join("empty")), 0o710);
        let stored = share.paths.load_manifest(share_id).unwrap();
        assert_eq!(stored.entries, remote.entries);
        assert_eq!(stored.directories, remote.directories);
    }

    #[cfg(unix)]
    #[test]
    fn metadata_only_permission_updates_do_not_need_file_payloads() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        let directory = root.join("private");
        let file = directory.join("config.txt");
        fs::create_dir_all(&directory).unwrap();
        let bytes = b"same content";
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let share_id = ShareId([13; 32]);
        let local_endpoint = SecretKey::from_bytes(&[14; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[15; 32]).public();
        let local = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "private/config.txt".to_owned(),
                file_entry(bytes, 0o000, timestamp(1, local_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "private".to_owned(),
                directory_entry(0o755, timestamp(1, local_endpoint)),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let share = active_share(&root, local.clone(), local_endpoint);
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::from([(
                "private/config.txt".to_owned(),
                file_entry(bytes, 0o600, timestamp(2, remote_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "private".to_owned(),
                directory_entry(0o700, timestamp(2, remote_endpoint)),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let (transfer, pending_updates) = make_transfer_request(&share, &local, &remote).unwrap();
        assert_eq!(pending_updates, 0);
        assert_eq!(transfer.download_paths, Vec::<String>::new());
        assert!(transfer.uploads.is_empty());

        let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
        assert_eq!(outcome.pending_downloads, 0);
        assert_eq!(fs::read(&file).unwrap(), bytes);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&directory), 0o700);
        let stored = share.paths.load_manifest(share_id).unwrap();
        assert_eq!(stored.entries, remote.entries);
        assert_eq!(stored.directories, remote.directories);
    }

    #[cfg(unix)]
    #[test]
    fn remote_transfer_applies_symlink_target_without_following_it() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();
        let share_id = ShareId([20; 32]);
        let local_endpoint = SecretKey::from_bytes(&[21; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[22; 32]).public();
        let share = active_share(&root, Manifest::empty(share_id, 0), local_endpoint);
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::new(),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::from([(
                "alias.txt".to_owned(),
                SymlinkEntry {
                    target: "target.txt".to_owned(),
                    version: timestamp(2, remote_endpoint),
                },
            )]),
            tombstones: BTreeMap::new(),
        };

        let outcome = apply_remote_transfer(&share, &remote, &[]).unwrap();
        assert_eq!(outcome.pending_downloads, 0);
        assert_eq!(
            fs::read_link(root.join("alias.txt")).unwrap(),
            Path::new("target.txt")
        );
        assert_eq!(
            share.paths.load_manifest(share_id).unwrap().symlinks,
            remote.symlinks
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_updates_work_inside_a_previously_read_only_directory() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        let directory = root.join("private");
        let file = directory.join("config.txt");
        fs::create_dir_all(&directory).unwrap();
        let old_bytes = b"old";
        let new_bytes = b"new";
        fs::write(&file, old_bytes).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        let share_id = ShareId([16; 32]);
        let local_endpoint = SecretKey::from_bytes(&[17; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[18; 32]).public();
        let directory_version = timestamp(1, remote_endpoint);
        let local = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "private/config.txt".to_owned(),
                file_entry(old_bytes, 0o444, timestamp(1, local_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "private".to_owned(),
                directory_entry(0o555, directory_version),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let share = active_share(&root, local, local_endpoint);
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::from([(
                "private/config.txt".to_owned(),
                file_entry(new_bytes, 0o600, timestamp(2, remote_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "private".to_owned(),
                directory_entry(0o555, directory_version),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let files = vec![FilePayload {
            path: "private/config.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(new_bytes)),
            content: URL_SAFE_NO_PAD.encode(new_bytes),
        }];

        let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();
        assert_eq!(outcome.pending_downloads, 0);
        assert_eq!(fs::read(&file).unwrap(), new_bytes);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&directory), 0o555);
    }

    #[cfg(unix)]
    #[test]
    fn remote_transfer_replaces_a_file_with_a_directory() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();
        let path = root.join("entry");
        fs::write(&path, "old file").unwrap();
        let share_id = ShareId([19; 32]);
        let local_endpoint = SecretKey::from_bytes(&[20; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[21; 32]).public();
        let local = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "entry".to_owned(),
                file_entry(b"old file", 0o600, timestamp(1, local_endpoint)),
            )]),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let share = active_share(&root, local, local_endpoint);
        let bytes = b"nested file";
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::from([(
                "entry/config.txt".to_owned(),
                file_entry(bytes, 0o640, timestamp(3, remote_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "entry".to_owned(),
                directory_entry(0o750, timestamp(2, remote_endpoint)),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let files = vec![FilePayload {
            path: "entry/config.txt".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            content: URL_SAFE_NO_PAD.encode(bytes),
        }];

        let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();

        assert_eq!(outcome.pending_downloads, 0);
        assert!(path.is_dir());
        assert_eq!(fs::read(path.join("config.txt")).unwrap(), bytes);
        assert_eq!(mode(&path), 0o750);
        assert_eq!(mode(&path.join("config.txt")), 0o640);
        let stored = share.paths.load_manifest(share_id).unwrap();
        assert_eq!(stored.entries, remote.entries);
        assert_eq!(stored.directories, remote.directories);
    }

    #[cfg(unix)]
    #[test]
    fn remote_transfer_replaces_an_empty_directory_with_a_file() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        let directory = root.join("entry");
        let nested_file = directory.join("old.txt");
        fs::create_dir_all(&directory).unwrap();
        fs::write(&nested_file, "old nested file").unwrap();
        let share_id = ShareId([22; 32]);
        let local_endpoint = SecretKey::from_bytes(&[23; 32]).public();
        let remote_endpoint = SecretKey::from_bytes(&[24; 32]).public();
        let local = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 1,
            entries: BTreeMap::from([(
                "entry/old.txt".to_owned(),
                file_entry(b"old nested file", 0o600, timestamp(1, local_endpoint)),
            )]),
            directories: BTreeMap::from([(
                "entry".to_owned(),
                directory_entry(0o700, timestamp(1, local_endpoint)),
            )]),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        };
        let share = active_share(&root, local, local_endpoint);
        let bytes = b"replacement file";
        let remote = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: 2,
            entries: BTreeMap::from([(
                "entry".to_owned(),
                file_entry(bytes, 0o640, timestamp(3, remote_endpoint)),
            )]),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::from([(
                "entry/old.txt".to_owned(),
                Tombstone {
                    version: timestamp(2, remote_endpoint),
                },
            )]),
        };
        let files = vec![FilePayload {
            path: "entry".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            content: URL_SAFE_NO_PAD.encode(bytes),
        }];

        let outcome = apply_remote_transfer(&share, &remote, &files).unwrap();

        assert_eq!(outcome.pending_downloads, 0);
        assert!(directory.is_file());
        assert_eq!(fs::read(&directory).unwrap(), bytes);
        assert_eq!(mode(&directory), 0o640);
        let stored = share.paths.load_manifest(share_id).unwrap();
        assert_eq!(stored.entries, remote.entries);
        assert_eq!(stored.directories, remote.directories);
        assert!(stored.tombstones == remote.tombstones);
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_missing_nested_path_does_not_create_parent_directories() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("share");
        fs::create_dir(&root).unwrap();

        remove_local_path(&root, "missing/config.txt").unwrap();

        assert!(!root.join("missing").exists());
    }
}
