use std::{cmp::Ordering, fmt, str::FromStr};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use rand::Rng as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const FORMAT_VERSION: u16 = 1;
pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ShareId(pub [u8; 32]);

impl ShareId {
    pub const HEX_LENGTH: usize = 64;

    pub fn random() -> Self {
        Self(rand::rng().random())
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != Self::HEX_LENGTH
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            bail!("share ID must be 64 lowercase hexadecimal characters");
        }
        let decoded = hex::decode(value).context("invalid share ID")?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow!("share ID has an invalid length"))?;
        Ok(Self(bytes))
    }

    pub fn matches_prefix(&self, value: &str) -> bool {
        !value.is_empty()
            && value.len() <= Self::HEX_LENGTH
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self.to_string().starts_with(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for ShareId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for ShareId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ShareId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ShareSecret([u8; 32]);

impl ShareSecret {
    pub fn random() -> Self {
        Self(rand::rng().random())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse_encoded(value: &str) -> Result<Self> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("share secret has an invalid encoding");
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| anyhow!("share secret has an invalid encoding"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow!("share secret has an invalid length"))?;
        if URL_SAFE_NO_PAD.encode(bytes) != value {
            bail!("share secret must use canonical base64url encoding");
        }
        Ok(Self(bytes))
    }

    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Debug for ShareSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareSecret(REDACTED)")
    }
}

impl Serialize for ShareSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded())
    }
}

impl<'de> Deserialize<'de> for ShareSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_encoded(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct ShareIdentity {
    pub share_id: ShareId,
    pub share_secret: ShareSecret,
}

impl ShareIdentity {
    pub fn random() -> Self {
        Self {
            share_id: ShareId::random(),
            share_secret: ShareSecret::random(),
        }
    }
}

pub fn endpoint_id_string(endpoint_id: &EndpointId) -> String {
    endpoint_id.to_string()
}

pub fn parse_endpoint_id(value: &str) -> Result<EndpointId> {
    let endpoint_id =
        EndpointId::from_str(value).map_err(|_| anyhow!("invalid Iroh endpoint ID"))?;
    if endpoint_id.to_string() != value {
        bail!("endpoint ID must use canonical lowercase hexadecimal encoding");
    }
    Ok(endpoint_id)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    pub format_version: u16,
    pub share_id: ShareId,
    pub share_secret: ShareSecret,
    pub name: String,
    pub local_directory: String,
    pub created_at_ms: u64,
    pub initial_peers: Vec<String>,
    #[serde(default)]
    pub initial_sync_complete: bool,
}

impl ShareConfig {
    pub fn validate(&self, expected_share_id: ShareId) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!(
                "unsupported share config format version {}",
                self.format_version
            );
        }
        if self.share_id != expected_share_id {
            bail!("share config ID does not match its directory");
        }
        validate_share_name(&self.name)?;
        if self.local_directory.is_empty() {
            bail!("share config has an empty local directory");
        }
        if self.initial_peers.len() > 64 {
            bail!("share config has too many initial peers");
        }
        for peer in &self.initial_peers {
            parse_endpoint_id(peer).context("share config contains an invalid initial peer")?;
        }
        Ok(())
    }
}

pub fn validate_share_name(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        bail!("share name must contain between 1 and 256 characters");
    }
    if trimmed != value {
        bail!("share name must not start or end with whitespace");
    }
    if value.chars().any(char::is_control) {
        bail!("share name must not contain control characters");
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownPeers {
    pub format_version: u16,
    pub peers: Vec<PeerRecord>,
}

impl KnownPeers {
    pub const fn empty() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            peers: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!(
                "unsupported known peers format version {}",
                self.format_version
            );
        }
        if self.peers.len() > 256 {
            bail!("known peers list exceeds its maximum size");
        }
        let mut seen = std::collections::BTreeSet::new();
        for peer in &self.peers {
            peer.validate()?;
            if !seen.insert(&peer.endpoint_id) {
                bail!("known peers list contains a duplicate endpoint ID");
            }
        }
        Ok(())
    }

    pub fn endpoint_ids(&self) -> Result<Vec<EndpointId>> {
        self.validate()?;
        self.peers
            .iter()
            .map(|peer| parse_endpoint_id(&peer.endpoint_id))
            .collect()
    }

    pub fn add_or_touch(&mut self, endpoint_id: &EndpointId, now_ms: u64) {
        let value = endpoint_id_string(endpoint_id);
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.endpoint_id == value) {
            existing.last_seen_at_ms = Some(now_ms);
            return;
        }
        self.peers.push(PeerRecord {
            endpoint_id: value,
            added_at_ms: now_ms,
            last_seen_at_ms: Some(now_ms),
        });
        self.peers
            .sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    }

    pub fn merge_endpoint_ids<I>(&mut self, endpoint_ids: I, now_ms: u64)
    where
        I: IntoIterator<Item = EndpointId>,
    {
        for endpoint_id in endpoint_ids {
            self.add_or_touch(&endpoint_id, now_ms);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRecord {
    pub endpoint_id: String,
    pub added_at_ms: u64,
    pub last_seen_at_ms: Option<u64>,
}

impl PeerRecord {
    pub fn validate(&self) -> Result<()> {
        parse_endpoint_id(&self.endpoint_id)
            .context("known peers contains an invalid endpoint ID")?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Stopped,
    Starting,
    Running,
    WaitingForPeers,
    Synchronizing,
    Degraded,
    Error,
}

impl RuntimeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::WaitingForPeers => "waiting_for_peers",
            Self::Synchronizing => "synchronizing",
            Self::Degraded => "degraded",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for RuntimeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncHealth {
    Unknown,
    Synchronized,
    Pending,
    Offline,
    Error,
}

impl SyncHealth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Synchronized => "synchronized",
            Self::Pending => "pending",
            Self::Offline => "offline",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for SyncHealth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    pub format_version: u16,
    pub process_id: u32,
    pub started_at_ms: u64,
    pub heartbeat_at_ms: u64,
    pub state: RuntimeState,
    pub health: SyncHealth,
    pub connected_peers: usize,
    pub pending_downloads: usize,
    pub pending_updates: usize,
    pub last_scan_at_ms: Option<u64>,
    pub last_remote_update_at_ms: Option<u64>,
    pub last_sync_at_ms: Option<u64>,
    pub last_connection_at_ms: Option<u64>,
    pub last_error: Option<String>,
}

impl RuntimeStatus {
    pub const fn stopped(now_ms: u64) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            process_id: 0,
            started_at_ms: now_ms,
            heartbeat_at_ms: now_ms,
            state: RuntimeState::Stopped,
            health: SyncHealth::Unknown,
            connected_peers: 0,
            pending_downloads: 0,
            pending_updates: 0,
            last_scan_at_ms: None,
            last_remote_update_at_ms: None,
            last_sync_at_ms: None,
            last_connection_at_ms: None,
            last_error: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!(
                "unsupported runtime status format version {}",
                self.format_version
            );
        }
        if self
            .last_error
            .as_ref()
            .is_some_and(|message| message.len() > 4096)
        {
            bail!("runtime status error message is too long");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HlcTimestamp {
    pub wall_ms: u64,
    pub counter: u32,
    pub author: [u8; 32],
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.wall_ms, self.counter, self.author).cmp(&(other.wall_ms, other.counter, other.author))
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockState {
    pub format_version: u16,
    pub last_wall_ms: u64,
    pub last_counter: u32,
}

impl ClockState {
    pub const fn new() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            last_wall_ms: 0,
            last_counter: 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!("unsupported clock format version {}", self.format_version);
        }
        Ok(())
    }

    pub fn tick(&mut self, now_ms: u64, author: [u8; 32]) -> Result<HlcTimestamp> {
        self.validate()?;
        if now_ms > self.last_wall_ms {
            self.last_wall_ms = now_ms;
            self.last_counter = 0;
        } else {
            self.last_counter = self
                .last_counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("hybrid logical clock counter overflow"))?;
        }
        Ok(HlcTimestamp {
            wall_ms: self.last_wall_ms,
            counter: self.last_counter,
            author,
        })
    }

    pub fn observe(&mut self, remote: HlcTimestamp, now_ms: u64) -> Result<()> {
        self.validate()?;
        let max_wall = self.last_wall_ms.max(remote.wall_ms).max(now_ms);
        let next_counter = if max_wall == self.last_wall_ms && max_wall == remote.wall_ms {
            self.last_counter
                .max(remote.counter)
                .checked_add(1)
                .ok_or_else(|| anyhow!("hybrid logical clock counter overflow"))?
        } else if max_wall == self.last_wall_ms {
            self.last_counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("hybrid logical clock counter overflow"))?
        } else if max_wall == remote.wall_ms {
            remote
                .counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("hybrid logical clock counter overflow"))?
        } else {
            0
        };
        self.last_wall_ms = max_wall;
        self.last_counter = next_counter;
        Ok(())
    }
}

impl Default for ClockState {
    fn default() -> Self {
        Self::new()
    }
}
