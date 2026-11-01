use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointId};
use tokio::{
    sync::Semaphore,
    task::{JoinError, JoinSet},
};
use tracing::{info, warn};

use crate::types::{RuntimeState, SyncHealth};

use super::{
    client::sync_with_peer,
    scheduling::{MAX_CONCURRENT_PEERS, SyncOutcome, select_due_peers, summarize_peer_outcomes},
    state::{ActiveShare, WINDOWS_SYMLINK_ERROR, unsupported_symlink_count, update_runtime},
};

type Completion = std::result::Result<(EndpointId, bool), JoinError>;

#[derive(Default)]
pub(super) struct PeerSessions {
    tasks: JoinSet<(EndpointId, bool)>,
    active: HashSet<EndpointId>,
}

impl PeerSessions {
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn spawn(
        &mut self,
        endpoint: &Endpoint,
        share: &Arc<ActiveShare>,
        peer: EndpointId,
        permits: &Arc<Semaphore>,
    ) {
        if self.active.insert(peer) {
            self.tasks.spawn(run_peer_session(
                endpoint.clone(),
                Arc::clone(share),
                peer,
                Arc::clone(permits),
            ));
        }
    }

    pub(super) async fn fill(
        &mut self,
        endpoint: &Endpoint,
        share: &Arc<ActiveShare>,
        permits: &Arc<Semaphore>,
    ) -> Result<()> {
        let available = MAX_CONCURRENT_PEERS.saturating_sub(self.len());
        if available == 0 {
            return Ok(());
        }
        for peer in due_peers(share, &self.active)
            .await?
            .into_iter()
            .take(available)
        {
            self.spawn(endpoint, share, peer, permits);
        }
        Ok(())
    }

    pub(super) async fn next(&mut self) -> Option<Completion> {
        self.tasks.join_next().await
    }

    pub(super) async fn finish(
        &mut self,
        completion: Completion,
        share: &Arc<ActiveShare>,
    ) -> Result<()> {
        let (peer, synchronized) = completion.context("peer synchronization task failed")?;
        self.active.remove(&peer);
        refresh_peer_status(share, synchronized, self.len()).await?;
        Ok(())
    }

    pub(super) async fn drain(&mut self, share: &Arc<ActiveShare>) -> Result<()> {
        let mut failure = None;
        while let Some(completion) = self.next().await {
            if let Err(error) = self.finish(completion, share).await
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

async fn run_peer_session(
    endpoint: Endpoint,
    share: Arc<ActiveShare>,
    peer: EndpointId,
    permits: Arc<Semaphore>,
) -> (EndpointId, bool) {
    let _permit = tokio::select! {
        biased;
        () = endpoint.closed() => return (peer, false),
        permit = permits.acquire() => permit.expect("peer semaphore is never closed"),
    };
    if endpoint.is_closed() {
        return (peer, false);
    }
    let generation = share.manifest_generation.load(Ordering::Relaxed);
    let network_generation = share.network_generation.load(Ordering::Acquire);
    info!(share_id = %share.share_id, peer_endpoint_id = %peer, "starting peer synchronization");
    let result = sync_with_peer(&endpoint, &share, peer).await;
    let outcome = result.as_ref().ok().map(|outcome| SyncOutcome {
        connected: true,
        pending_downloads: outcome.pending_downloads,
        pending_updates: outcome.pending_updates,
        ..SyncOutcome::default()
    });
    share
        .record_peer_attempt(peer, generation, network_generation, outcome.as_ref())
        .await;
    match result {
        Ok(outcome) => {
            info!(share_id = %share.share_id, peer_endpoint_id = %peer, pending_downloads = outcome.pending_downloads, pending_updates = outcome.pending_updates, "peer synchronization completed");
            (peer, true)
        }
        Err(error) => {
            if !endpoint.is_closed() {
                warn!(share_id = %share.share_id, peer_endpoint_id = %peer, error = %format_args!("{error:#}"), "peer synchronization failed");
            }
            (peer, false)
        }
    }
}

async fn due_peers(
    share: &Arc<ActiveShare>,
    active: &HashSet<EndpointId>,
) -> Result<Vec<EndpointId>> {
    let mut peers = share.paths.load_known_peer_ids(share.share_id)?;
    peers.retain(|peer| *peer != share.local_endpoint_id);
    let generation = share.manifest_generation.load(Ordering::Relaxed);
    let mut schedules = share.peer_schedule.lock().await;
    schedules.retain(|peer, _| peers.contains(peer) || active.contains(peer));
    peers.retain(|peer| !active.contains(peer));
    select_due_peers(&mut peers, &schedules, Instant::now(), generation);
    drop(schedules);
    Ok(peers)
}

pub(super) async fn refresh_peer_status(
    share: &Arc<ActiveShare>,
    synchronized: bool,
    in_flight: usize,
) -> Result<SyncOutcome> {
    let schedules = share.peer_schedule.lock().await;
    let mut outcome = summarize_peer_outcomes(&schedules);
    outcome.unsupported_items = unsupported_symlink_count(&share.manifest_snapshot()?.manifest);
    let generation = share.manifest_generation.load(Ordering::Relaxed);
    let confirmed = schedules.values().any(|schedule| {
        schedule.last_outcome.is_some() && schedule.last_attempted_generation == generation
    });
    let failed = schedules.values().any(|schedule| schedule.failures > 0);
    let (state, health) = if outcome.unsupported_items > 0 && outcome.connected {
        (RuntimeState::Degraded, SyncHealth::Error)
    } else if outcome.connected
        && confirmed
        && in_flight == 0
        && outcome.pending_downloads == 0
        && outcome.pending_updates == 0
    {
        (RuntimeState::Running, SyncHealth::Synchronized)
    } else if outcome.connected || in_flight > 0 {
        (RuntimeState::Synchronizing, SyncHealth::Pending)
    } else {
        (RuntimeState::WaitingForPeers, SyncHealth::Offline)
    };
    update_runtime(share, |status, now_ms| {
        status.state = state;
        status.health = health;
        status.connected_peers = outcome.connected_peers;
        status.pending_downloads = outcome.pending_downloads;
        status.pending_updates = outcome.pending_updates;
        if synchronized {
            status.last_sync_at_ms = Some(now_ms);
        }
        status.last_error = if outcome.unsupported_items > 0 && outcome.connected {
            Some(WINDOWS_SYMLINK_ERROR.to_owned())
        } else if failed && !outcome.connected && in_flight == 0 {
            Some("could not connect to a known peer".to_owned())
        } else {
            None
        };
    })?;
    drop(schedules);
    Ok(outcome)
}

pub(super) async fn sync_known_peers(
    endpoint: &Endpoint,
    share: &Arc<ActiveShare>,
) -> Result<SyncOutcome> {
    let mut pending = VecDeque::from(due_peers(share, &HashSet::new()).await?);
    let mut sessions = PeerSessions::default();
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PEERS));
    let mut failure = None;
    while !pending.is_empty() || !sessions.is_empty() {
        while sessions.len() < MAX_CONCURRENT_PEERS {
            let Some(peer) = pending.pop_front() else {
                break;
            };
            sessions.spawn(endpoint, share, peer, &permits);
        }
        if failure.is_none()
            && let Err(error) = refresh_peer_status(share, false, sessions.len()).await
        {
            endpoint.close().await;
            pending.clear();
            failure = Some(error);
        }
        if let Some(completion) = sessions.next().await
            && let Err(error) = sessions.finish(completion, share).await
        {
            endpoint.close().await;
            pending.clear();
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    refresh_peer_status(share, false, 0).await
}
