//! Peer synchronization engine.
//!
//! The engine is split into small private modules:
//!
//! - `state`: per-share runtime state, manifest cache, and runtime status persistence.
//! - `registry`: share lookup, initial-sync handoff, and registry loading.
//! - `scheduling`: peer retry scheduling and scan cadence decisions.
//! - `lifecycle`: watchers, accept loop, sync cycles, and shutdown.
//! - `client`: outbound peer synchronization.
//! - `incoming`: inbound connection and stream handling.
//! - `auth`: per-stream HMAC authentication handshake.
//! - `wire`: versioned protocol messages, their validation, and JSON frames.
//! - `transfer`: transfer planning, chunk streaming, and remote apply.
//! - `local`: shared-directory path, permission, and staged-write helpers.
//! - `transport`, `io`, `diagnostics`, `connectivity`: Iroh plumbing.

use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::{
    identity::DeviceIdentity,
    storage::DataPaths,
    types::{RuntimeState, ShareId, SyncHealth},
};

mod auth;
mod client;
mod connection_cache;
mod connectivity;
mod diagnostics;
mod discovery;
mod incoming;
mod io;
mod lifecycle;
mod local;
mod peer_sessions;
mod registry;
mod scheduling;
mod state;
mod transfer;
mod transport;
mod wire;
mod workers;

pub use registry::{InitialSyncStatus, attempt_initial_sync};

use connectivity::spawn_connectivity_monitor;
use lifecycle::{run_cycles, spawn_accept_loop, spawn_pool_maintenance, start_watchers};
use registry::load_registry;
use state::{set_runtime_error, set_runtime_state, set_stopped};
use transport::bind_endpoint;

pub const SYNCBOX_ALPN: &[u8] = b"syncbox/2";

pub(crate) const HASH_BUFFER_BYTES: usize = 64 * 1024;
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_INCOMING_HANDLERS: usize = 32;

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
    let maintenance_task = spawn_pool_maintenance(endpoint.clone(), &registry);
    let scan_notify = Arc::new(Notify::new());
    let connectivity_task = (!once).then(|| {
        spawn_connectivity_monitor(endpoint.clone(), registry.clone(), Arc::clone(&scan_notify))
    });
    let watchers = if once {
        Vec::new()
    } else {
        start_watchers(&registry, &scan_notify)
    };
    let result = run_cycles(&endpoint, &registry, once, &scan_notify).await;
    drop(watchers);
    endpoint.close().await;
    if let Err(error) = maintenance_task.await {
        warn!(error = %error, "connection pool maintenance failed during shutdown");
    }
    if let Some(task) = connectivity_task
        && let Err(error) = task.await
    {
        warn!(error = %error, "connectivity monitor failed during shutdown");
    }
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

pub(crate) fn run_blocking<T>(operation: impl FnOnce() -> T) -> T {
    if matches!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

#[cfg(test)]
mod tests;
