use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use iroh::Endpoint;
use notify::{RecursiveMode, Watcher};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tracing::{error, warn};

use super::{
    HANDSHAKE_TIMEOUT, MAX_INCOMING_HANDLERS, diagnostics,
    incoming::handle_incoming,
    local::config_root,
    peer_sessions::sync_known_peers,
    registry::ShareRegistry,
    run_blocking,
    scheduling::scan_due,
    state::{ActiveShare, refresh_heartbeat, scan_and_save},
    workers::run_share_workers,
};

pub const MAX_CONCURRENT_SHARES: usize = 4;
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
pub fn scan_event_is_relevant(event: &notify::Event) -> bool {
    use notify::EventKind;
    use notify::event::{AccessKind, AccessMode, MetadataKind, ModifyKind};

    event.need_rescan()
        || !matches!(
            event.kind,
            EventKind::Access(
                AccessKind::Open(_) | AccessKind::Read | AccessKind::Close(AccessMode::Read)
            ) | EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime))
        )
}

pub fn start_watchers(
    registry: &ShareRegistry,
    scan_notify: &Arc<Notify>,
) -> Vec<notify::RecommendedWatcher> {
    let mut watchers = Vec::new();
    for share in registry.values() {
        let Ok(root) = share.config().and_then(|config| config_root(&config)) else {
            continue;
        };
        let dirty = Arc::clone(&share.scan_dirty);
        let active = Arc::clone(&share.watcher_active);
        let notify = Arc::clone(scan_notify);
        let share_id = share.share_id;
        active.store(true, Ordering::Release);
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let unreliable = event.as_ref().map_or(true, notify::Event::need_rescan);
            if unreliable && active.swap(false, Ordering::AcqRel) {
                warn!(share_id = %share_id, "file watcher unreliable; using five-second scans");
            }
            if event.as_ref().map_or(true, scan_event_is_relevant)
                && !dirty.swap(true, Ordering::AcqRel)
            {
                notify.notify_one();
            }
        });
        if let Ok(watcher) = watcher.and_then(|mut watcher| {
            watcher.watch(&root, RecursiveMode::Recursive)?;
            Ok(watcher)
        }) {
            watchers.push(watcher);
        } else {
            share.watcher_active.store(false, Ordering::Release);
            warn!(share_id = %share.share_id, "file watcher unavailable; using five-second scans");
        }
    }
    watchers
}

pub async fn drain_incoming_handlers(handlers: &mut tokio::task::JoinSet<()>) {
    while let Some(result) = handlers.join_next().await {
        if let Err(error) = result {
            warn!(
                error = %format_args!("{error:#}"),
                "incoming synchronization task failed"
            );
        }
    }
}

pub fn spawn_accept_loop(endpoint: Endpoint, registry: ShareRegistry) -> JoinHandle<()> {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(MAX_INCOMING_HANDLERS));
        let stream_permits = Arc::new(Semaphore::new(MAX_INCOMING_HANDLERS));
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
                    let stream_permits = Arc::clone(&stream_permits);
                    handlers.spawn(async move {
                        let _permit = permit;
                        let started = Instant::now();
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
                        diagnostics::trace_connection(&connection, false, Some(started.elapsed()));
                        let peer_endpoint_id = connection.remote_id();
                        if let Err(error) = handle_incoming(connection, registry, stream_permits).await {
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

pub fn spawn_pool_maintenance(endpoint: Endpoint, registry: &ShareRegistry) -> JoinHandle<()> {
    let pool = registry
        .values()
        .next()
        .map(|share| Arc::clone(&share.connections));
    tokio::spawn(async move {
        let Some(pool) = pool else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                biased;
                () = endpoint.closed() => break,
                _ = interval.tick() => pool.maintain().await,
            }
        }
    })
}

pub async fn run_cycles(
    endpoint: &Endpoint,
    registry: &ShareRegistry,
    once: bool,
    scan_notify: &Notify,
) -> Result<()> {
    // Connection and transfer deadlines may be much longer than the status freshness window.
    // Refresh status independently so a healthy process is never reported as stopped merely
    // because one peer is slow or unreachable.
    let heartbeat_task = spawn_heartbeat_loop(registry.clone());
    let result = if once {
        run_sync_cycle_until_shutdown(endpoint, registry, wait_for_shutdown_signal())
            .await
            .map(|_| ())
    } else {
        run_share_workers(endpoint, registry, scan_notify, wait_for_shutdown_signal()).await
    };
    heartbeat_task.abort();
    let _ = heartbeat_task.await;
    result
}

pub async fn run_sync_cycle_until_shutdown(
    endpoint: &Endpoint,
    registry: &ShareRegistry,
    shutdown: impl std::future::Future<Output = Result<()>>,
) -> Result<bool> {
    // Keep the cycle future alive after shutdown wins. Its JoinSet owns work that may be inside
    // block_in_place, which Tokio cannot cancel.
    let cycle = run_sync_cycle(endpoint, registry);
    tokio::pin!(cycle);
    tokio::select! {
        shutdown_result = shutdown => {
            endpoint.close().await;
            cycle.await;
            shutdown_result?;
            Ok(false)
        }
        () = &mut cycle => Ok(true),
    }
}

pub fn spawn_heartbeat_loop(registry: ShareRegistry) -> JoinHandle<()> {
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

pub async fn wait_for_shutdown_signal() -> Result<()> {
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

pub async fn run_sync_cycle(endpoint: &Endpoint, registry: &ShareRegistry) {
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

pub async fn scan_active_share(share: &Arc<ActiveShare>) -> Result<bool> {
    let config = share.config()?;
    if config.initial_sync_complete {
        let due = scan_due(
            *share.last_scan.lock().await,
            Instant::now(),
            share.watcher_active.load(Ordering::Acquire),
            share.scan_dirty.load(Ordering::Acquire),
        );
        if due {
            share.scan_dirty.swap(false, Ordering::AcqRel);
            // Keep the operation lock held while blocking work runs; a detached blocking task
            // could outlive a cancelled synchronization cycle during shutdown.
            let _operation_lock = share.operation_lock.lock().await;
            if let Err(error) = run_blocking(|| scan_and_save(share, &config)) {
                share.scan_dirty.store(true, Ordering::Release);
                return Err(error);
            }
            *share.last_scan.lock().await = Some(Instant::now());
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn sync_active_share(endpoint: &Endpoint, share: &Arc<ActiveShare>) -> Result<()> {
    scan_active_share(share).await?;
    sync_known_peers(endpoint, share).await.map(|_| ())
}
