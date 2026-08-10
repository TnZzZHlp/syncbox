use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use rand::Rng as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
    time::timeout,
};

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

pub const SYNCBOX_ALPN: &[u8] = b"syncbox/1";
const AUTH_MAGIC: [u8; 4] = *b"SBXA";
const CLIENT_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32;
const SERVER_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32 + 32;
const MAX_CONTROL_FRAME_BYTES: usize = 96 * 1024 * 1024;
const MAX_TRANSFER_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRANSFER_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_FILES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SYNC_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INCOMING_HANDLERS: usize = 32;
const SYNC_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct ActiveShare {
    paths: DataPaths,
    share_id: ShareId,
    config: Arc<RwLock<ShareConfig>>,
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

    for share in registry.values() {
        set_runtime_state(&share, RuntimeState::Starting, SyncHealth::Unknown, None)?;
    }

    let endpoint = match Endpoint::builder(presets::N0)
        .secret_key(identity.secret_key())
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
    {
        Ok(endpoint) => endpoint,
        Err(error) => {
            for share in registry.values() {
                let _ = set_runtime_error(&share, "unable to start Iroh endpoint");
            }
            return Err(anyhow!(error).context("unable to start the global Iroh endpoint"));
        }
    };

    let accept_task = spawn_accept_loop(endpoint.clone(), registry.clone());
    let result = run_cycles(&endpoint, &registry, once).await;
    for share in registry.values() {
        let _ = set_stopped(&share);
    }
    endpoint.close().await;
    accept_task.abort();
    let _ = accept_task.await;
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
    let Ok(endpoint) = Endpoint::builder(presets::N0)
        .secret_key(identity.secret_key())
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
    else {
        set_runtime_state(
            &share,
            RuntimeState::WaitingForPeers,
            SyncHealth::Offline,
            None,
        )?;
        return Ok(false);
    };
    let result = sync_known_peers(&endpoint, &share).await;
    endpoint.close().await;
    if let Ok(outcome) = result {
        if outcome.connected {
            set_stopped(&share)?;
            Ok(true)
        } else {
            set_runtime_state(
                &share,
                RuntimeState::WaitingForPeers,
                SyncHealth::Offline,
                None,
            )?;
            Ok(false)
        }
    } else {
        set_runtime_state(
            &share,
            RuntimeState::WaitingForPeers,
            SyncHealth::Offline,
            None,
        )?;
        Ok(false)
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

fn spawn_accept_loop(endpoint: Endpoint, registry: ShareRegistry) -> JoinHandle<()> {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(MAX_INCOMING_HANDLERS));
        loop {
            let Some(incoming) = endpoint.accept().await else {
                break;
            };
            // Drop excess unauthenticated connections rather than allowing stalled peers to
            // create unbounded tasks or consume every stream handler.
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let registry = registry.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(Ok(connection)) = timeout(HANDSHAKE_TIMEOUT, incoming).await else {
                    return;
                };
                let _ = handle_incoming(connection, registry).await;
            });
        }
    })
}

async fn run_cycles(endpoint: &Endpoint, registry: &ShareRegistry, once: bool) -> Result<()> {
    // Connection and transfer deadlines may be much longer than the status freshness window.
    // Refresh status independently so a healthy process is never reported as stopped merely
    // because one peer is slow or unreachable.
    let heartbeat_task = spawn_heartbeat_loop(registry.clone());
    let result = tokio::select! {
        shutdown = wait_for_shutdown_signal() => {
            shutdown?;
            Ok(())
        }
        () = run_sync_cycle(endpoint, registry) => {
            if once {
                Ok(())
            } else {
                run_periodic_cycles(endpoint, registry).await
            }
        }
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
        tokio::select! {
            shutdown = wait_for_shutdown_signal() => {
                shutdown?;
                return Ok(());
            }
            () = run_sync_cycle(endpoint, registry) => {}
        }
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
    for share in registry.values() {
        let _ = sync_active_share(endpoint, &share).await;
    }
}

async fn sync_active_share(endpoint: &Endpoint, share: &Arc<ActiveShare>) -> Result<()> {
    let config = share.config()?;
    if config.initial_sync_complete {
        // Protect only local state changes. Never hold this lock while waiting for a remote
        // response: two peers can legitimately dial each other at the same time.
        let _operation_lock = share.operation_lock.lock().await;
        scan_and_save(share, &config)?;
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
        set_runtime_state(
            share,
            RuntimeState::WaitingForPeers,
            SyncHealth::Offline,
            None,
        )?;
        return Ok(SyncOutcome::default());
    }

    set_runtime_state(
        share,
        RuntimeState::Synchronizing,
        SyncHealth::Pending,
        None,
    )?;
    let mut outcome = SyncOutcome::default();
    let mut had_connection_error = false;
    for peer in candidates {
        if let Ok(Ok(peer_outcome)) =
            timeout(SYNC_EXCHANGE_TIMEOUT, sync_with_peer(endpoint, share, peer)).await
        {
            outcome.connected = true;
            outcome.connected_peers = outcome.connected_peers.saturating_add(1);
            outcome.pending_downloads = outcome
                .pending_downloads
                .saturating_add(peer_outcome.pending_downloads);
            outcome.pending_updates = outcome
                .pending_updates
                .saturating_add(peer_outcome.pending_updates);
        } else {
            had_connection_error = true;
            set_runtime_error(share, "could not connect to a known peer")?;
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
    Ok(outcome)
}

async fn sync_with_peer(
    endpoint: &Endpoint,
    share: &Arc<ActiveShare>,
    expected_peer: EndpointId,
) -> Result<PeerSyncOutcome> {
    let config = share.config()?;
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

    let outbound_manifest = if config.initial_sync_complete {
        share.paths.load_manifest(share.share_id)?
    } else {
        Manifest::empty(share.share_id, current_time_ms())
    };
    let known_peers = known_peer_strings(share, &expected_peer)?;
    write_json_frame(
        &mut send,
        &SyncRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest: outbound_manifest.clone(),
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
    let (transfer, pending_updates) = {
        let _operation_lock = share.operation_lock.lock().await;
        make_transfer_request(share, &outbound_manifest, &response.manifest)?
    };
    write_json_frame(&mut send, &transfer).await?;
    send.finish()
        .context("unable to finish sync request stream")?;
    let final_response: TransferResponse = read_json_frame(&mut recv).await?;
    validate_transfer_response(&final_response, share.share_id)?;
    let applied = {
        let _operation_lock = share.operation_lock.lock().await;
        let applied =
            apply_remote_transfer(share, &final_response.manifest, &final_response.files)?;
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
            scan_and_save(share, &updated_config)?;
        }
        applied
    };
    connection.close(0_u8.into(), b"sync complete");
    Ok(PeerSyncOutcome {
        pending_downloads: applied.pending_downloads,
        pending_updates,
    })
}

async fn handle_incoming(connection: Connection, registry: ShareRegistry) -> Result<()> {
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
        &connection.remote_id(),
        &share.local_endpoint_id,
    )?;
    let server_nonce: [u8; 32] = rand::rng().random();
    let server_hello = make_server_hello(
        &config,
        &connection.remote_id(),
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
        merge_remote_peers(
            &share,
            request.known_peers.iter(),
            Some(connection.remote_id()),
        )?;
        let local_manifest = share.paths.load_manifest(share.share_id)?;
        let known_peers = known_peer_strings(&share, &connection.remote_id())?;
        (local_manifest, known_peers)
    };
    write_json_frame(
        &mut send,
        &SyncResponse {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest: local_manifest,
            known_peers,
        },
    )
    .await?;

    let transfer: TransferRequest = read_json_frame(&mut recv).await?;
    validate_transfer_request(&transfer, share.share_id)?;
    let (applied, final_manifest, files) = {
        let _operation_lock = share.operation_lock.lock().await;
        let applied = apply_remote_transfer(&share, &transfer.manifest, &transfer.files)?;
        let final_manifest = share.paths.load_manifest(share.share_id)?;
        let files = build_file_payloads(&share, &final_manifest, &transfer.download_paths)?;
        (applied, final_manifest, files)
    };
    write_json_frame(
        &mut send,
        &TransferResponse {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest: final_manifest,
            files,
        },
    )
    .await?;
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
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncRequest {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
    known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncResponse {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
    known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferRequest {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
    download_paths: Vec<String>,
    files: Vec<FilePayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferResponse {
    protocol_version: u16,
    share_id: ShareId,
    manifest: Manifest,
    files: Vec<FilePayload>,
}

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
    request.manifest.validate(share_id)?;
    validate_wire_peers(&request.known_peers)
}

fn validate_sync_response(response: &SyncResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("sync response has an incompatible protocol or share ID");
    }
    response.manifest.validate(share_id)?;
    validate_wire_peers(&response.known_peers)
}

fn validate_transfer_request(request: &TransferRequest, share_id: ShareId) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION || request.share_id != share_id {
        bail!("file transfer request has an incompatible protocol or share ID");
    }
    request.manifest.validate(share_id)?;
    validate_path_list(&request.download_paths)?;
    validate_file_payloads(&request.files, &request.manifest)
}

fn validate_transfer_response(response: &TransferResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("file transfer response has an incompatible protocol or share ID");
    }
    response.manifest.validate(share_id)?;
    validate_file_payloads(&response.files, &response.manifest)
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

fn validate_file_payloads(files: &[FilePayload], manifest: &Manifest) -> Result<()> {
    if files.len() > MAX_TRANSFER_FILES {
        bail!("network transfer contains too many files");
    }
    let mut total = 0_usize;
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
        if file.content.len() > MAX_TRANSFER_FILE_BYTES.saturating_mul(2) {
            bail!("network file payload is too large");
        }
        let data = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        if URL_SAFE_NO_PAD.encode(&data) != file.content {
            bail!("network file payload must use canonical base64url encoding");
        }
        if data.len() > MAX_TRANSFER_FILE_BYTES || data.len() as u64 != entry.size {
            bail!("network file payload has an invalid length");
        }
        let hash = hex::encode(Sha256::digest(&data));
        if hash != entry.sha256 {
            bail!("network file payload has an invalid hash");
        }
        total = total
            .checked_add(data.len())
            .ok_or_else(|| anyhow!("network transfer length overflow"))?;
        if total > MAX_TRANSFER_TOTAL_BYTES {
            bail!("network transfer is too large");
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
    for (path, remote_entry) in &remote.entries {
        let remote_record = ManifestRecordRef::File(remote_entry);
        if matches!(select_record(local.record(path), Some(remote_record)), Some(selected) if selected.version() == remote_record.version() && selected.is_tombstone() == remote_record.is_tombstone())
        {
            let local_same = local.entries.get(path).is_some_and(|entry| {
                entry.version == remote_entry.version && entry.sha256 == remote_entry.sha256
            });
            if !local_same {
                download_paths.push(path.clone());
            }
        }
    }
    download_paths.sort_unstable();
    download_paths.dedup();
    download_paths.truncate(MAX_TRANSFER_FILES);

    let mut upload_paths = Vec::new();
    for (path, local_entry) in &local.entries {
        let local_record = ManifestRecordRef::File(local_entry);
        let selected = select_record(Some(local_record), remote.record(path));
        let local_wins = matches!(selected, Some(winner) if winner.version() == local_record.version() && !winner.is_tombstone());
        let remote_same = remote.entries.get(path).is_some_and(|entry| {
            entry.version == local_entry.version && entry.sha256 == local_entry.sha256
        });
        if local_wins && !remote_same {
            upload_paths.push(path.clone());
        }
    }
    upload_paths.sort_unstable();
    let requested_uploads = upload_paths.len();
    upload_paths.truncate(MAX_TRANSFER_FILES);
    let files = build_file_payloads(share, local, &upload_paths)?;
    let pending_updates = requested_uploads.saturating_sub(files.len());
    Ok((
        TransferRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            manifest: local.clone(),
            download_paths,
            files,
        },
        pending_updates,
    ))
}

fn build_file_payloads(
    share: &Arc<ActiveShare>,
    manifest: &Manifest,
    paths: &[String],
) -> Result<Vec<FilePayload>> {
    validate_path_list(paths)?;
    let root = config_root(&share.config()?)?;
    let mut files = Vec::new();
    let mut total = 0_usize;
    for path in paths {
        let Some(entry) = manifest.entries.get(path) else {
            continue;
        };
        if entry.size > MAX_TRANSFER_FILE_BYTES as u64 {
            continue;
        }
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
        if after_read.len() != entry.size
            || bytes.len() > MAX_TRANSFER_FILE_BYTES
            || bytes.len() as u64 != entry.size
        {
            continue;
        }
        if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            continue;
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow!("file transfer length overflow"))?;
        if total > MAX_TRANSFER_TOTAL_BYTES {
            break;
        }
        files.push(FilePayload {
            path: path.clone(),
            sha256: entry.sha256.clone(),
            content: URL_SAFE_NO_PAD.encode(bytes),
        });
    }
    Ok(files)
}

/// Applies only remote records whose file data is present. This avoids claiming a large or
/// unstable file is synchronized before it was safely written to the shared directory.
fn apply_remote_transfer(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    files: &[FilePayload],
) -> Result<ApplyOutcome> {
    remote.validate(share.share_id)?;
    validate_file_payloads(files, remote)?;
    let config = share.config()?;
    let root = config_root(&config)?;
    let local = share.paths.load_manifest(share.share_id)?;
    let mut file_data = BTreeMap::new();
    for file in files {
        let bytes = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        file_data.insert(file.path.clone(), bytes);
    }

    let mut candidate = local.clone();
    let mut pending_downloads = 0_usize;
    let mut applied_records = 0_usize;
    let all_paths = local
        .all_paths()
        .union(&remote.all_paths())
        .cloned()
        .collect::<Vec<_>>();
    for path in all_paths {
        let local_record = local.record(&path);
        let remote_record = remote.record(&path);
        let Some(selected) = select_record(local_record, remote_record) else {
            continue;
        };
        let selected_remote = remote_record_wins(local_record, remote_record);
        if !selected_remote {
            continue;
        }
        match selected {
            ManifestRecordRef::Tombstone(tombstone) => {
                remove_local_file(&root, &path)?;
                candidate.entries.remove(&path);
                candidate.tombstones.insert(path, tombstone.clone());
                applied_records = applied_records.saturating_add(1);
            }
            ManifestRecordRef::File(entry) => {
                if let Some(bytes) = file_data.get(&path) {
                    write_local_file(share, &root, &path, bytes)?;
                    candidate.tombstones.remove(&path);
                    candidate.entries.insert(path, entry.clone());
                    applied_records = applied_records.saturating_add(1);
                } else {
                    // If an exact local file already has the selected version, no payload is needed.
                    let already_present = local.entries.get(&path).is_some_and(|local_entry| {
                        local_entry.version == entry.version && local_entry.sha256 == entry.sha256
                    });
                    if !already_present {
                        pending_downloads = pending_downloads.saturating_add(1);
                    }
                }
            }
        }
    }
    candidate.scanned_at_ms = current_time_ms();
    candidate.validate(share.share_id)?;
    if candidate.entries != local.entries || candidate.tombstones != local.tombstones {
        observe_manifest_clock(share, &candidate)?;
        share.paths.save_manifest(&candidate)?;
    }
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
    share.paths.save_clock(share.share_id, &scanned.clock)?;
    share.paths.save_manifest(&scanned.manifest)?;
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

fn write_local_file(
    share: &Arc<ActiveShare>,
    root: &Path,
    manifest_path: &str,
    bytes: &[u8],
) -> Result<()> {
    let target = safe_local_path(root, manifest_path, true)?;
    if let Ok(metadata) = fs::symlink_metadata(&target) {
        if metadata.file_type().is_symlink() {
            bail!("refusing to replace symbolic link {}", target.display());
        }
        if metadata.is_dir() {
            bail!("refusing to replace directory {}", target.display());
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
                fs::write(&target, bytes).with_context(|| {
                    format!("unable to install downloaded file {}", target.display())
                })?;
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
            Err(error) => Err(error)
                .with_context(|| format!("unable to install downloaded file {}", target.display())),
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn remove_local_file(root: &Path, manifest_path: &str) -> Result<()> {
    let target = safe_local_path(root, manifest_path, false)?;
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to delete symbolic link {}", target.display())
        }
        Ok(metadata) if metadata.is_file() => fs::remove_file(&target)
            .with_context(|| format!("unable to remove shared file {}", target.display())),
        Ok(metadata) if metadata.is_dir() => {
            bail!("refusing to delete directory {}", target.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("unable to inspect {}", target.display())),
    }
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
    use iroh::SecretKey;

    use super::*;
    use crate::types::{FORMAT_VERSION, ShareSecret};

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
}
