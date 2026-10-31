use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{
    Endpoint, EndpointId, SecretKey, TransportAddr,
    address_lookup::{AddrFilter, EndpointData},
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt as _,
    sync::{Mutex, Notify, Semaphore},
    time::timeout,
};

#[cfg(unix)]
use crate::manifest::DirectoryEntry;

use super::*;
use crate::{
    chunk::MAX_CHUNK_BYTES,
    manifest::{MANIFEST_FORMAT_VERSION, Manifest, ManifestEntry, SymlinkEntry, Tombstone},
    network::{
        auth::*, client::*, incoming::*, io::IO_IDLE_TIMEOUT, io::ProgressIo, lifecycle::*,
        local::*, registry::*, scheduling::*, state::*, transfer::*, transport::ConnectionPool,
        wire::*,
    },
    runtime::RuntimeStatusCache,
    types::{
        ClockState, FORMAT_VERSION, HlcTimestamp, KnownPeers, PROTOCOL_VERSION, RuntimeStatus,
        ShareConfig, ShareId, ShareSecret,
    },
};

mod auth;
mod connection_cache;
mod lifecycle;
mod local;
mod scheduling;
mod state;
mod transfer;
mod transport;
mod wire;

fn config() -> (ShareConfig, EndpointId, EndpointId) {
    let client = SecretKey::from_bytes(&[1; 32]).public();
    let server = SecretKey::from_bytes(&[2; 32]).public();
    (
        ShareConfig {
            format_version: FORMAT_VERSION,
            share_id: ShareId([3; 32]),
            share_secret: ShareSecret::from_bytes([4; 32]),
            name: "test".to_owned(),
            local_directory: "/tmp/test".to_owned(),
            created_at_ms: 0,
            initial_peers: vec![server.to_string()],
            initial_sync_complete: true,
        },
        client,
        server,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn active_share(root: &Path, manifest: Manifest, endpoint: EndpointId) -> Arc<ActiveShare> {
    let paths = DataPaths::from_root(root.parent().unwrap().join("state"));
    let config = ShareConfig {
        format_version: FORMAT_VERSION,
        share_id: manifest.share_id,
        share_secret: ShareSecret::from_bytes([9; 32]),
        name: "test".to_owned(),
        local_directory: root.to_string_lossy().into_owned(),
        created_at_ms: 0,
        initial_peers: Vec::new(),
        initial_sync_complete: true,
    };
    paths
        .create_share_state(
            &config,
            &manifest,
            &ClockState::new(),
            &KnownPeers::empty(),
            &RuntimeStatus::stopped(0),
        )
        .unwrap();
    Arc::new(ActiveShare {
        paths,
        share_id: manifest.share_id,
        config: Arc::new(RwLock::new(config)),
        receive_lock: Arc::new(Mutex::new(())),
        operation_lock: Arc::new(Mutex::new(())),
        runtime_status: Arc::new(std::sync::Mutex::new(RuntimeStatusCache::default())),
        manifest_generation: Arc::new(AtomicU64::new(0)),
        network_generation: Arc::new(AtomicU64::new(0)),
        manifest_cache: Arc::new(std::sync::Mutex::new(None)),
        peer_schedule: Arc::new(Mutex::new(HashMap::new())),
        connections: Arc::new(ConnectionPool::default()),
        scan_dirty: Arc::new(AtomicBool::new(true)),
        watcher_active: Arc::new(AtomicBool::new(false)),
        last_scan: Arc::new(Mutex::new(None)),
        local_endpoint_id: endpoint,
    })
}

fn timestamp(wall_ms: u64, endpoint: EndpointId) -> HlcTimestamp {
    HlcTimestamp {
        wall_ms,
        counter: 0,
        author: *endpoint.as_bytes(),
    }
}

#[cfg(unix)]
fn file_entry(bytes: &[u8], permissions: u16, version: HlcTimestamp) -> ManifestEntry {
    ManifestEntry {
        size: bytes.len() as u64,
        modified_at_ns: 0,
        sha256: hex::encode(Sha256::digest(bytes)),
        permissions: Some(permissions),
        version,
    }
}

#[cfg(unix)]
fn directory_entry(permissions: u16, version: HlcTimestamp) -> DirectoryEntry {
    DirectoryEntry {
        permissions: Some(permissions),
        version,
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u16 {
    (fs::metadata(path).unwrap().permissions().mode() & 0o7777) as u16
}
