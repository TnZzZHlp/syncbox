use std::sync::Arc;

use anyhow::{Result, anyhow};
use iroh::Endpoint;
use tokio::{
    sync::{Notify, Semaphore},
    time::sleep,
};
use tracing::error;

use super::{
    lifecycle::{MAX_CONCURRENT_SHARES, sync_active_share},
    registry::ShareRegistry,
    scheduling::SYNC_INTERVAL,
    state::ActiveShare,
};

pub(super) async fn run_share_workers(
    endpoint: &Endpoint,
    registry: &ShareRegistry,
    scan_notify: &Notify,
    shutdown: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_SHARES));
    let mut workers = tokio::task::JoinSet::new();
    let mut wakeups = Vec::new();
    for share in registry.values() {
        let wakeup = Arc::new(Notify::new());
        wakeups.push(Arc::clone(&wakeup));
        workers.spawn(run_share_worker(
            endpoint.clone(),
            share,
            wakeup,
            Arc::clone(&permits),
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
                    Some(Ok(())) if !endpoint.is_closed() => Err(anyhow!("share synchronization worker stopped unexpectedly")),
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
        if let Err(error) = worker {
            error!(error = %error, "share synchronization worker failed during shutdown");
            if result.is_ok() {
                result =
                    Err(anyhow!(error)
                        .context("share synchronization worker failed during shutdown"));
            }
        }
    }
    result
}

async fn run_share_worker(
    endpoint: Endpoint,
    share: Arc<ActiveShare>,
    wakeup: Arc<Notify>,
    permits: Arc<Semaphore>,
) {
    loop {
        let permit = tokio::select! {
            biased;
            () = endpoint.closed() => return,
            permit = permits.acquire() => permit.expect("share semaphore is never closed"),
        };
        if endpoint.is_closed() {
            return;
        }
        let result = sync_active_share(&endpoint, &share).await;
        drop(permit);
        if let Err(error) = result
            && !endpoint.is_closed()
        {
            error!(share_id = %share.share_id, error = %format_args!("{error:#}"), "synchronization cycle failed");
        }
        tokio::select! {
            biased;
            () = endpoint.closed() => return,
            () = sleep(SYNC_INTERVAL) => {}
            () = wakeup.notified() => {}
        }
    }
}
