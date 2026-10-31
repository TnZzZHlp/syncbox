use std::time::Duration;

use iroh::{TransportAddr, endpoint::Connection};
use tracing::{Level, debug};

pub(super) fn trace_connection(connection: &Connection, reused: bool, setup: Option<Duration>) {
    if !tracing::enabled!(Level::DEBUG) {
        return;
    }
    let paths = connection.paths();
    let selected = paths.iter().find(iroh::endpoint::Path::is_selected);
    let transport = selected
        .as_ref()
        .map_or("pending", |path| match path.remote_addr() {
            TransportAddr::Ip(address) if address.is_ipv6() => "ipv6",
            TransportAddr::Ip(_) => "ipv4",
            TransportAddr::Relay(_) => "relay",
            _ => "other",
        });
    debug!(
        peer_endpoint_id = %connection.remote_id(),
        connection_id = connection.stable_id(),
        reused,
        setup_ms = ?setup.map(|duration| duration.as_millis()),
        open_paths = paths.len(),
        selected_transport = transport,
        rtt_ms = ?selected.map(|path| path.rtt().as_millis()),
        "peer connection path snapshot"
    );
}
