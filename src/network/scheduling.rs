use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use iroh::EndpointId;
use rand::RngExt as _;

use super::registry::InitialSyncStatus;

pub const SYNC_INTERVAL: Duration = Duration::from_secs(5);
pub const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(60);
pub const IDLE_PEER_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_CONCURRENT_PEERS: usize = 2;

pub fn scan_due(last_scan: Option<Instant>, now: Instant, watching: bool, dirty: bool) -> bool {
    last_scan.is_none_or(|last| {
        let elapsed = now.saturating_duration_since(last);
        (dirty && elapsed >= SYNC_INTERVAL)
            || elapsed
                >= if watching {
                    FULL_SCAN_INTERVAL
                } else {
                    SYNC_INTERVAL
                }
    })
}

#[derive(Default)]
pub struct PeerSchedule {
    pub(crate) next_at: Option<Instant>,
    pub(crate) last_attempted_generation: u64,
    pub(crate) failures: u32,
    pub(crate) last_outcome: Option<PeerSyncOutcome>,
}

impl PeerSchedule {
    pub(crate) const fn retry_now(&mut self) {
        self.next_at = None;
        self.failures = 0;
    }

    pub(crate) fn due(&self, now: Instant, generation: u64) -> bool {
        generation != self.last_attempted_generation || self.next_at.is_none_or(|at| now >= at)
    }

    pub(crate) fn after_attempt(
        &mut self,
        now: Instant,
        generation: u64,
        outcome: Option<&SyncOutcome>,
    ) {
        self.last_attempted_generation = generation;
        self.last_outcome =
            outcome
                .filter(|outcome| outcome.connected)
                .map(|outcome| PeerSyncOutcome {
                    pending_downloads: outcome.pending_downloads,
                    pending_updates: outcome.pending_updates,
                });
        let delay = match outcome {
            Some(outcome) if outcome.connected => {
                self.failures = 0;
                if outcome.pending_downloads > 0 || outcome.pending_updates > 0 {
                    SYNC_INTERVAL
                } else {
                    IDLE_PEER_INTERVAL
                }
            }
            _ => {
                let jitter = Duration::from_millis(rand::rng().random_range(0..1000));
                let delay = (SYNC_INTERVAL * (1_u32 << self.failures.min(3)) + jitter)
                    .min(IDLE_PEER_INTERVAL);
                self.failures = self.failures.saturating_add(1);
                delay
            }
        };
        self.next_at = Some(now + delay);
    }
}

#[derive(Default)]
pub struct SyncOutcome {
    pub(crate) connected: bool,
    pub(crate) connected_peers: usize,
    pub(crate) pending_downloads: usize,
    pub(crate) pending_updates: usize,
    pub(crate) unsupported_items: usize,
}

pub const fn initial_sync_status(outcome: &SyncOutcome) -> InitialSyncStatus {
    if !outcome.connected {
        InitialSyncStatus::Offline
    } else if outcome.pending_downloads == 0
        && outcome.pending_updates == 0
        && outcome.unsupported_items == 0
    {
        InitialSyncStatus::Complete
    } else {
        InitialSyncStatus::Pending
    }
}

pub struct PeerSyncOutcome {
    pub(crate) pending_downloads: usize,
    pub(crate) pending_updates: usize,
}

pub fn summarize_peer_outcomes(schedules: &HashMap<EndpointId, PeerSchedule>) -> SyncOutcome {
    let mut summary = SyncOutcome::default();
    for outcome in schedules
        .values()
        .filter_map(|schedule| schedule.last_outcome.as_ref())
    {
        summary.connected = true;
        summary.connected_peers = summary.connected_peers.saturating_add(1);
        summary.pending_downloads = summary
            .pending_downloads
            .saturating_add(outcome.pending_downloads);
        summary.pending_updates = summary
            .pending_updates
            .saturating_add(outcome.pending_updates);
    }
    summary
}

pub fn select_due_peers(
    candidates: &mut Vec<EndpointId>,
    schedules: &HashMap<EndpointId, PeerSchedule>,
    now: Instant,
    generation: u64,
) {
    candidates.retain(|peer| {
        schedules
            .get(peer)
            .is_none_or(|schedule| schedule.due(now, generation))
    });
    candidates.sort_by_key(|peer| schedules.get(peer).and_then(|schedule| schedule.next_at));
    candidates.truncate(4);
}
