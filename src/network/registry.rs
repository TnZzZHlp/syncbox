use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64},
    },
};

use anyhow::Result;
use iroh::EndpointId;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{
    identity::DeviceIdentity,
    runtime::RuntimeStatusCache,
    storage::DataPaths,
    types::{RuntimeState, ShareId, SyncHealth},
};

use super::{
    client::sync_known_peers,
    scheduling::initial_sync_status,
    state::{ActiveShare, set_runtime_state, set_stopped},
    transport::{ConnectionPool, bind_endpoint},
};

#[derive(Clone)]
pub struct ShareRegistry {
    pub(crate) shares: Arc<HashMap<ShareId, Arc<ActiveShare>>>,
}

impl ShareRegistry {
    pub(crate) fn get(&self, share_id: ShareId) -> Option<Arc<ActiveShare>> {
        self.shares.get(&share_id).cloned()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = Arc<ActiveShare>> + '_ {
        self.shares.values().cloned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialSyncStatus {
    Complete,
    Pending,
    Offline,
}

/// Attempts the mandatory initial peer connection after `join` has already persisted its state.
///
/// The registry lock keeps removal from racing this handoff. Peer-level connection failures are
/// normal and return `Offline`; state and lifecycle errors propagate to the caller.
pub async fn attempt_initial_sync(
    paths: DataPaths,
    identity: DeviceIdentity,
    share_id: ShareId,
) -> Result<InitialSyncStatus> {
    let _registry_lock = paths.acquire_registry_lock()?;
    let Some(_device_lock) = paths.try_acquire_device_run_lock()? else {
        return Ok(InitialSyncStatus::Offline);
    };
    let Some(_share_lock) = paths.try_acquire_share_lock(share_id)? else {
        return Ok(InitialSyncStatus::Offline);
    };
    let registry = load_registry(&paths, identity.endpoint_id(), &[share_id])?;
    let Some(share) = registry.get(share_id) else {
        return Ok(InitialSyncStatus::Offline);
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
            return Err(cleanup_initial_sync_error(
                &share,
                anyhow::Error::new(error).context("unable to start Iroh endpoint for initial sync"),
            ));
        }
    };
    let result = sync_known_peers(&endpoint, &share).await;
    endpoint.close().await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => return Err(cleanup_initial_sync_error(&share, error)),
    };
    if outcome.connected {
        let status = initial_sync_status(&outcome);
        match status {
            InitialSyncStatus::Complete => {
                info!(share_id = %share_id, "initial synchronization completed");
            }
            InitialSyncStatus::Pending => {
                info!(
                    share_id = %share_id,
                    pending_downloads = outcome.pending_downloads,
                    pending_updates = outcome.pending_updates,
                    "initial synchronization remains pending"
                );
            }
            InitialSyncStatus::Offline => unreachable!("connected outcome cannot be offline"),
        }
        set_stopped(&share)?;
        return Ok(status);
    }

    info!(share_id = %share_id, "initial synchronization found no online peers");
    set_runtime_state(
        &share,
        RuntimeState::WaitingForPeers,
        SyncHealth::Offline,
        None,
    )?;
    set_stopped(&share)?;
    Ok(InitialSyncStatus::Offline)
}

pub fn cleanup_initial_sync_error(share: &Arc<ActiveShare>, error: anyhow::Error) -> anyhow::Error {
    let cleanup = set_runtime_state(
        share,
        RuntimeState::WaitingForPeers,
        SyncHealth::Offline,
        Some("initial synchronization failed"),
    )
    .and_then(|()| set_stopped(share));
    if let Err(cleanup_error) = cleanup {
        return error.context(format!(
            "initial synchronization failed; unable to reset runtime state: {cleanup_error:#}"
        ));
    }
    error.context("initial synchronization failed")
}

pub fn load_registry(
    paths: &DataPaths,
    endpoint_id: EndpointId,
    share_ids: &[ShareId],
) -> Result<ShareRegistry> {
    let mut shares = HashMap::new();
    let connections = Arc::new(ConnectionPool::default());
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
                runtime_status: Arc::new(std::sync::Mutex::new(RuntimeStatusCache::default())),
                manifest_generation: Arc::new(AtomicU64::new(0)),
                network_generation: Arc::new(AtomicU64::new(0)),
                manifest_cache: Arc::new(std::sync::Mutex::new(None)),
                peer_schedule: Arc::new(Mutex::new(HashMap::new())),
                connections: Arc::clone(&connections),
                scan_dirty: Arc::new(AtomicBool::new(true)),
                watcher_active: Arc::new(AtomicBool::new(false)),
                last_scan: Arc::new(Mutex::new(None)),
                local_endpoint_id: endpoint_id,
            }),
        );
    }
    Ok(ShareRegistry {
        shares: Arc::new(shares),
    })
}
