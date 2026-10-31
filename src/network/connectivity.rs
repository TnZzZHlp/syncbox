use std::{collections::BTreeSet, sync::Arc, time::Duration};

use iroh::{Endpoint, Watcher as _};
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{Instant, sleep_until},
};
use tracing::info;

use super::ShareRegistry;

const RECOVERY_COOLDOWN: Duration = Duration::from_secs(5);

pub(super) fn spawn_connectivity_monitor(
    endpoint: Endpoint,
    registry: ShareRegistry,
    sync_notify: Arc<Notify>,
) -> JoinHandle<()> {
    let mut addresses = endpoint.watch_addr();
    addresses.get();
    let mut relays = endpoint.home_relay_status().map(|statuses| {
        statuses
            .into_iter()
            .filter(iroh::endpoint::RelayStatus::is_connected)
            .map(|status| status.url().to_string())
            .collect::<BTreeSet<_>>()
    });
    let mut connected_relays = relays.get();
    tokio::spawn(async move {
        let mut pending = false;
        let mut next_retry = Instant::now();
        loop {
            tokio::select! {
                biased;
                () = endpoint.closed() => break,
                updated = addresses.updated() => {
                    if updated.is_err() {
                        break;
                    }
                    pending = true;
                }
                updated = relays.updated() => {
                    let Ok(updated) = updated else {
                        break;
                    };
                    pending |= !updated.is_subset(&connected_relays);
                    connected_relays = updated;
                }
                () = sleep_until(next_retry), if pending => {
                    for share in registry.values() {
                        share.retry_peers().await;
                    }
                    sync_notify.notify_one();
                    info!("network connectivity changed; scheduling peer retries");
                    pending = false;
                    next_retry = Instant::now() + RECOVERY_COOLDOWN;
                }
            }
        }
    })
}
