use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointId,
    address_lookup::{AddrFilter, DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream, VarInt, presets},
};
use tokio::{
    sync::{Mutex, Semaphore},
    time::timeout,
};

use super::{SYNCBOX_ALPN, diagnostics::trace_connection};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONCURRENT_DIALS: usize = 8;
pub(super) const MAX_CONNECTION_STREAMS: u32 = 8;
pub(super) const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

type ConnectionSlot = Arc<Mutex<Option<Connection>>>;

pub(super) struct ConnectionPool {
    connections: Mutex<HashMap<EndpointId, ConnectionSlot>>,
    dial_permits: Semaphore,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            dial_permits: Semaphore::new(MAX_CONCURRENT_DIALS),
        }
    }
}

impl ConnectionPool {
    async fn connect(&self, endpoint: &Endpoint, peer: EndpointId) -> Result<Connection> {
        if endpoint.is_closed() {
            bail!("Iroh endpoint is closed");
        }
        let slot = {
            let mut connections = self.connections.lock().await;
            connections.retain(|_, slot| {
                Arc::strong_count(slot) > 1
                    || slot.try_lock().map_or(true, |connection| {
                        connection
                            .as_ref()
                            .is_some_and(|connection| connection.close_reason().is_none())
                    })
            });
            Arc::clone(connections.entry(peer).or_default())
        };
        let mut cached = slot.lock().await;
        if let Some(connection) = cached
            .as_ref()
            .filter(|connection| connection.close_reason().is_none())
        {
            let connection = connection.clone();
            drop(cached);
            trace_connection(&connection, true, None);
            return Ok(connection);
        }
        *cached = None;
        let _permit = self
            .dial_permits
            .acquire()
            .await
            .expect("dial semaphore is never closed");
        if endpoint.is_closed() {
            bail!("Iroh endpoint is closed");
        }
        let started = Instant::now();
        let connection = timeout(CONNECT_TIMEOUT, endpoint.connect(peer, SYNCBOX_ALPN))
            .await
            .context("timed out connecting to known Iroh endpoint")?
            .context("unable to connect to known Iroh endpoint")?;
        if connection.remote_id() != peer {
            connection.close(0_u8.into(), b"unexpected peer");
            bail!("connected Iroh endpoint does not match the expected peer");
        }
        *cached = Some(connection.clone());
        drop(cached);
        trace_connection(&connection, false, Some(started.elapsed()));
        Ok(connection)
    }

    async fn invalidate(&self, peer: EndpointId, connection: &Connection) {
        let slot = self.connections.lock().await.get(&peer).cloned();
        if let Some(slot) = slot {
            let mut cached = slot.lock().await;
            if cached
                .as_ref()
                .is_some_and(|cached| cached.stable_id() == connection.stable_id())
            {
                *cached = None;
            }
        }
    }

    pub(super) async fn open_stream(
        &self,
        endpoint: &Endpoint,
        peer: EndpointId,
    ) -> Result<(SendStream, RecvStream)> {
        for attempt in 0..2 {
            let connection = self.connect(endpoint, peer).await?;
            let result = timeout(CONNECT_TIMEOUT, connection.open_bi()).await;
            match result {
                Ok(Ok(stream)) => return Ok(stream),
                result => {
                    if attempt == 1 || connection.close_reason().is_none() {
                        return result
                            .context("timed out opening sync stream")?
                            .context("unable to open sync stream");
                    }
                    self.invalidate(peer, &connection).await;
                }
            }
        }
        unreachable!("stream attempts always return")
    }
}

pub(super) async fn bind_endpoint(
    secret_key: iroh::SecretKey,
) -> std::result::Result<Endpoint, iroh::endpoint::BindError> {
    Endpoint::builder(presets::N0)
        .clear_address_lookup()
        .address_lookup(PkarrPublisher::n0_dns().addr_filter(AddrFilter::unfiltered()))
        .address_lookup(PkarrResolver::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .transport_config(
            QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONNECTION_STREAMS))
                .build(),
        )
        .secret_key(secret_key)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
}

#[cfg(test)]
mod tests {
    use iroh::address_lookup::memory::MemoryLookup;

    use super::*;

    #[tokio::test]
    async fn closed_connections_are_replaced_on_the_next_exchange() {
        let lookup = MemoryLookup::new();
        let client = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .alpns(vec![SYNCBOX_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![SYNCBOX_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        lookup.add_endpoint_info(server.addr());
        let receiver = server.clone();
        let handler = tokio::spawn(async move {
            let first = receiver.accept().await.unwrap().await.unwrap();
            first.close(0_u8.into(), b"retry");
            let next = receiver.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = next.accept_bi().await.unwrap();
            let payload = recv.read_to_end(16).await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
        });
        let pool = ConnectionPool::default();
        timeout(Duration::from_secs(10), async {
            pool.connect(&client, server.id())
                .await
                .unwrap()
                .closed()
                .await;
            let (mut send, mut recv) = pool.open_stream(&client, server.id()).await.unwrap();
            send.write_all(b"reconnected").await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(16).await.unwrap(), b"reconnected");
        })
        .await
        .unwrap();
        handler.await.unwrap();
        client.close().await;
        server.close().await;
    }
}
