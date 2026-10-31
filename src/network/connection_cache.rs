use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use iroh::{EndpointId, endpoint::Connection};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub(super) const MAX_CACHED_CONNECTIONS: usize = 32;
pub(super) const MAX_CONNECTION_STREAMS: u32 = 8;
pub(super) const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

pub(super) struct PeerSlot {
    pub(super) connection: Mutex<Option<Connection>>,
    stream_permits: Arc<Semaphore>,
    last_used: StdMutex<Instant>,
}

impl Default for PeerSlot {
    fn default() -> Self {
        Self {
            connection: Mutex::new(None),
            stream_permits: Arc::new(Semaphore::new(
                usize::try_from(MAX_CONNECTION_STREAMS).expect("stream limit fits usize"),
            )),
            last_used: StdMutex::new(Instant::now()),
        }
    }
}

impl PeerSlot {
    fn last_used(&self) -> Instant {
        *self
            .last_used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn touch(&self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    fn close(self: Arc<Self>) {
        if let Ok(slot) = Arc::try_unwrap(self)
            && let Some(connection) = slot.connection.into_inner()
        {
            connection.close(0_u8.into(), b"sync cache idle");
        }
    }

    pub(super) async fn lease(self: Arc<Self>) -> StreamLease {
        let permit = Arc::clone(&self.stream_permits)
            .acquire_owned()
            .await
            .expect("stream semaphore is never closed");
        self.touch();
        StreamLease {
            slot: self,
            _permit: permit,
        }
    }
}

pub(super) struct StreamLease {
    slot: Arc<PeerSlot>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.slot.touch();
    }
}

#[derive(Default)]
pub(super) struct ConnectionCache {
    peers: Mutex<HashMap<EndpointId, Arc<PeerSlot>>>,
}

impl ConnectionCache {
    fn reap(peers: &mut HashMap<EndpointId, Arc<PeerSlot>>, now: Instant) {
        let expired: Vec<_> = peers
            .iter()
            .filter_map(|(peer, slot)| {
                if Arc::strong_count(slot) != 1 {
                    return None;
                }
                let connection = slot.connection.try_lock().ok()?;
                (connection
                    .as_ref()
                    .is_none_or(|connection| connection.close_reason().is_some())
                    || now.saturating_duration_since(slot.last_used()) >= CONNECTION_IDLE_TIMEOUT)
                    .then_some(*peer)
            })
            .collect();
        for peer in expired {
            if let Some(slot) = peers.remove(&peer) {
                slot.close();
            }
        }
    }

    pub(super) async fn maintain(&self) {
        let mut peers = self.peers.lock().await;
        Self::reap(&mut peers, Instant::now());
    }

    pub(super) async fn get(&self, peer: EndpointId) -> Option<Arc<PeerSlot>> {
        self.peers.lock().await.get(&peer).cloned()
    }

    pub(super) async fn slot(&self, peer: EndpointId) -> Result<Arc<PeerSlot>> {
        let mut peers = self.peers.lock().await;
        Self::reap(&mut peers, Instant::now());
        if let Some(slot) = peers.get(&peer) {
            return Ok(Arc::clone(slot));
        }
        if peers.len() >= MAX_CACHED_CONNECTIONS {
            let oldest = peers
                .iter()
                .filter(|(_, slot)| Arc::strong_count(slot) == 1)
                .min_by_key(|(_, slot)| slot.last_used())
                .map(|(peer, _)| *peer)
                .ok_or_else(|| anyhow!("connection pool is busy with active peers"))?;
            if let Some(slot) = peers.remove(&oldest) {
                slot.close();
            }
        }
        let slot = Arc::new(PeerSlot::default());
        peers.insert(peer, Arc::clone(&slot));
        drop(peers);
        Ok(slot)
    }
}
