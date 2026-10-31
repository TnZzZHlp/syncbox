use std::sync::Arc;

use anyhow::{Result, anyhow};
use iroh::Endpoint;
use tokio::{
    sync::{Notify, Semaphore},
    time::MissedTickBehavior,
};
use tracing::error;

use super::{
    lifecycle::{MAX_CONCURRENT_SHARES, scan_active_share},
    peer_sessions::{PeerSessions, refresh_peer_status},
    registry::ShareRegistry,
    scheduling::{MAX_CONCURRENT_PEERS, SYNC_INTERVAL},
    state::ActiveShare,
};

pub(super) async fn run_share_workers(
    endpoint: &Endpoint,
    registry: &ShareRegistry,
    scan_notify: &Notify,
    shutdown: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let scans = Arc::new(Semaphore::new(MAX_CONCURRENT_SHARES));
    let peers = Arc::new(Semaphore::new(MAX_CONCURRENT_SHARES * MAX_CONCURRENT_PEERS));
    let mut workers = tokio::task::JoinSet::new();
    let mut wakeups = Vec::new();
    for share in registry.values() {
        let wakeup = Arc::new(Notify::new());
        wakeups.push(Arc::clone(&wakeup));
        workers.spawn(run_share_worker(
            endpoint.clone(),
            share,
            wakeup,
            Arc::clone(&scans),
            Arc::clone(&peers),
        ));
    }
    tokio::pin!(shutdown);
    let mut result = loop {
        tokio::select! {
            biased;
            () = endpoint.closed() => break Ok(()),
            result = &mut shutdown => break result,
            worker = workers.join_next() => {
                break match worker {
                    Some(Err(error)) => Err(anyhow!(error).context("share synchronization worker failed")),
                    Some(Ok(Err(error))) => Err(error),
                    Some(Ok(Ok(()))) if !endpoint.is_closed() => Err(anyhow!("share synchronization worker stopped unexpectedly")),
                    _ => Ok(()),
                };
            }
            () = scan_notify.notified() => {
                for wakeup in &wakeups {
                    wakeup.notify_one();
                }
            }
        }
    };
    endpoint.close().await;
    while let Some(worker) = workers.join_next().await {
        let failure = match worker {
            Ok(result) => result.err(),
            Err(error) => {
                Some(anyhow!(error).context("share synchronization worker failed during shutdown"))
            }
        };
        if let Some(error) = failure {
            error!(error = %format_args!("{error:#}"), "share synchronization worker failed during shutdown");
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    result
}

async fn run_share_worker(
    endpoint: Endpoint,
    share: Arc<ActiveShare>,
    wakeup: Arc<Notify>,
    scans: Arc<Semaphore>,
    peers: Arc<Semaphore>,
) -> Result<()> {
    let mut sessions = PeerSessions::default();
    let mut interval = tokio::time::interval(SYNC_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let result = loop {
        let completion = tokio::select! {
            biased;
            () = endpoint.closed() => break Ok(()),
            completion = sessions.next(), if !sessions.is_empty() => completion,
            _ = interval.tick() => None,
            () = wakeup.notified() => None,
        };
        if let Some(completion) = completion
            && let Err(error) = sessions.finish(completion, &share).await
        {
            break Err(error);
        }
        let permit = tokio::select! {
            biased;
            () = endpoint.closed() => break Ok(()),
            permit = scans.acquire() => permit.expect("scan semaphore is never closed"),
        };
        if endpoint.is_closed() {
            break Ok(());
        }
        let scan = scan_active_share(&share).await;
        drop(permit);
        match scan {
            Ok(true) => interval.reset(),
            Ok(false) => {}
            Err(error) => {
                error!(share_id = %share.share_id, error = %format_args!("{error:#}"), "share scan failed");
                continue;
            }
        }
        if let Err(error) = sessions.fill(&endpoint, &share, &peers).await {
            break Err(error);
        }
        if let Err(error) = refresh_peer_status(&share, false, sessions.len()).await {
            break Err(error);
        }
    };
    if result.is_err() {
        endpoint.close().await;
    }
    let drained = sessions.drain(&share).await;
    result.and(drained)
}
