use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use anyhow::{Result, anyhow, bail};
use iroh::EndpointId;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::{
    manifest::{Manifest, current_time_ms, scan_manifest_cached_after_validation},
    runtime::RuntimeStatusCache,
    storage::DataPaths,
    types::{RuntimeState, RuntimeStatus, ShareConfig, ShareId, SyncHealth, parse_endpoint_id},
};

use super::{
    local::config_root,
    scheduling::{PeerSchedule, SyncOutcome},
    transport::ConnectionPool,
};

/// Error reported when a peer publishes symbolic links on a platform that cannot create them.
pub const WINDOWS_SYMLINK_ERROR: &str = "symbolic links are unsupported on Windows";
#[derive(Clone)]
pub struct ActiveShare {
    pub(crate) paths: DataPaths,
    pub(crate) share_id: ShareId,
    pub(crate) config: Arc<RwLock<ShareConfig>>,
    pub(crate) receive_lock: Arc<Mutex<()>>,
    pub(crate) operation_lock: Arc<Mutex<()>>,
    pub(crate) runtime_status: Arc<std::sync::Mutex<RuntimeStatusCache>>,
    pub(crate) manifest_generation: Arc<AtomicU64>,
    pub(crate) network_generation: Arc<AtomicU64>,
    pub(crate) manifest_cache: Arc<std::sync::Mutex<Option<Arc<ManifestSnapshot>>>>,
    pub(crate) peer_schedule: Arc<Mutex<HashMap<EndpointId, PeerSchedule>>>,
    pub(crate) connections: Arc<ConnectionPool>,
    pub(crate) scan_dirty: Arc<AtomicBool>,
    pub(crate) watcher_active: Arc<AtomicBool>,
    pub(crate) last_scan: Arc<Mutex<Option<Instant>>>,
    pub(crate) local_endpoint_id: EndpointId,
}

pub struct ManifestSnapshot {
    pub(crate) digest: [u8; 32],
    pub(crate) manifest: Manifest,
}

impl ManifestSnapshot {
    // DataPaths validates both loaded and saved manifests before they enter this cache.
    pub(crate) fn from_validated(manifest: Manifest) -> Self {
        Self {
            digest: manifest.sync_digest_after_validation(),
            manifest,
        }
    }
}

impl ActiveShare {
    pub(crate) async fn retry_peers(&self) {
        self.network_generation.fetch_add(1, Ordering::AcqRel);
        let mut schedules = self.peer_schedule.lock().await;
        for schedule in schedules.values_mut() {
            schedule.retry_now();
        }
    }

    pub(crate) async fn record_peer_attempt(
        &self,
        peer: EndpointId,
        generation: u64,
        network_generation: u64,
        outcome: Option<&SyncOutcome>,
    ) {
        let mut schedules = self.peer_schedule.lock().await;
        let schedule = schedules.entry(peer).or_default();
        schedule.after_attempt(Instant::now(), generation, outcome);
        if self.network_generation.load(Ordering::Acquire) != network_generation {
            schedule.retry_now();
        }
        drop(schedules);
    }

    pub(crate) fn manifest_snapshot(&self) -> Result<Arc<ManifestSnapshot>> {
        let mut cache = self
            .manifest_cache
            .lock()
            .map_err(|_| anyhow!("manifest cache lock was poisoned"))?;
        if let Some(snapshot) = cache.as_ref() {
            return Ok(Arc::clone(snapshot));
        }
        let manifest = self.paths.load_manifest(self.share_id)?;
        let snapshot = Arc::new(ManifestSnapshot::from_validated(manifest));
        *cache = Some(Arc::clone(&snapshot));
        drop(cache);
        Ok(snapshot)
    }

    pub(crate) fn save_manifest(&self, manifest: Manifest) -> Result<()> {
        if manifest.share_id != self.share_id {
            bail!("manifest belongs to another share");
        }
        let mut cache = self
            .manifest_cache
            .lock()
            .map_err(|_| anyhow!("manifest cache lock was poisoned"))?;
        if let Err(error) = self.paths.save_manifest(&manifest) {
            *cache = None;
            self.manifest_generation.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        *cache = Some(Arc::new(ManifestSnapshot::from_validated(manifest)));
        self.manifest_generation.fetch_add(1, Ordering::Relaxed);
        drop(cache);
        Ok(())
    }

    pub(crate) fn config(&self) -> Result<ShareConfig> {
        self.config
            .read()
            .map_err(|_| anyhow!("share configuration lock was poisoned"))
            .map(|config| config.clone())
    }

    pub(crate) fn replace_config(&self, config: ShareConfig) -> Result<()> {
        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("share configuration lock was poisoned"))?;
        *guard = config;
        drop(guard);
        Ok(())
    }
}

#[cfg(windows)]
pub fn unsupported_symlink_count(manifest: &Manifest) -> usize {
    manifest.symlinks.len()
}

#[cfg(not(windows))]
pub const fn unsupported_symlink_count(_manifest: &Manifest) -> usize {
    0
}

pub fn scan_and_save(share: &Arc<ActiveShare>, config: &ShareConfig) -> Result<()> {
    let root = config_root(config)?;
    let snapshot = share.manifest_snapshot()?;
    let clock = share.paths.load_clock(share.share_id)?;
    let now_ms = current_time_ms();
    let scanned = scan_manifest_cached_after_validation(
        &root,
        &snapshot.manifest,
        clock,
        &share.local_endpoint_id,
        now_ms,
    )?;
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
        share.save_manifest(scanned.manifest.into_owned())?;
    }
    update_runtime(share, |status, _| {
        status.last_scan_at_ms = Some(now_ms);
        if scanned.changes > 0 {
            status.pending_updates = scanned.changes;
        }
    })?;
    Ok(())
}

pub fn merge_remote_peers<'a, I>(
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

pub fn known_peer_strings(share: &Arc<ActiveShare>, remote: &EndpointId) -> Result<Vec<String>> {
    let peers = share.paths.load_known_peers(share.share_id)?;
    let local_id = share.local_endpoint_id.to_string();
    let remote_id = remote.to_string();
    let mut values = peers
        .peers
        .into_iter()
        .filter(|peer| peer.endpoint_id != local_id && peer.endpoint_id != remote_id)
        .map(|peer| peer.endpoint_id)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values.truncate(256);
    Ok(values)
}

pub fn update_runtime<F>(share: &Arc<ActiveShare>, update: F) -> Result<()>
where
    F: FnOnce(&mut RuntimeStatus, u64),
{
    share
        .runtime_status
        .lock()
        .map_err(|_| anyhow!("runtime status lock was poisoned"))?
        .update(
            &share.paths,
            share.share_id,
            current_time_ms(),
            false,
            update,
        )
}

pub fn set_runtime_state(
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

pub fn set_runtime_error(share: &Arc<ActiveShare>, message: &str) -> Result<()> {
    update_runtime(share, |status, _| {
        status.state = RuntimeState::Degraded;
        status.health = SyncHealth::Offline;
        status.connected_peers = 0;
        status.last_error = Some(message.to_owned());
    })
}

pub fn refresh_heartbeat(share: &Arc<ActiveShare>) -> Result<()> {
    share
        .runtime_status
        .lock()
        .map_err(|_| anyhow!("runtime status lock was poisoned"))?
        .update(
            &share.paths,
            share.share_id,
            current_time_ms(),
            true,
            |_, _| {},
        )
}

pub fn set_stopped(share: &Arc<ActiveShare>) -> Result<()> {
    update_runtime(share, |status, _| {
        status.process_id = 0;
        status.state = RuntimeState::Stopped;
        status.connected_peers = 0;
    })
}
