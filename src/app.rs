use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use iroh::EndpointId;
use serde::Serialize;

use crate::{
    identity,
    manifest::{Manifest, current_time_ms, scan_manifest},
    network,
    storage::DataPaths,
    ticket::ShareTicket,
    types::{
        ClockState, FORMAT_VERSION, KnownPeers, PeerRecord, RuntimeState, RuntimeStatus,
        ShareConfig, ShareId, ShareIdentity, SyncHealth, endpoint_id_string, parse_endpoint_id,
        validate_share_name,
    },
};

pub const STATUS_HEARTBEAT_STALE_MS: u64 = 15_000;

#[derive(Clone)]
pub struct App {
    paths: DataPaths,
}

impl App {
    pub fn discover() -> Result<Self> {
        Ok(Self {
            paths: DataPaths::discover()?,
        })
    }

    #[cfg(test)]
    pub const fn with_paths(paths: DataPaths) -> Self {
        Self { paths }
    }

    pub const fn paths(&self) -> &DataPaths {
        &self.paths
    }

    pub fn device_id(&self) -> Result<EndpointId> {
        Ok(identity::load_or_create(&self.paths)?.endpoint_id())
    }

    pub fn init(
        &self,
        requested_directory: &Path,
        requested_name: Option<&str>,
    ) -> Result<InitResult> {
        let local_directory = normalize_local_directory(requested_directory)?;
        self.ensure_directory_isolated_from_data_root(&local_directory)?;
        let _registry_lock = self.paths.acquire_registry_lock()?;
        if let Some(existing_share_id) = self.find_share_for_directory(&local_directory)? {
            bail!(
                "local directory {} is already registered by share {}",
                local_directory.display(),
                existing_share_id
            );
        }

        let identity = identity::load_or_create(&self.paths)?;
        let endpoint_id = identity.endpoint_id();
        let share_identity = self.new_unused_share_identity()?;
        let now_ms = current_time_ms();
        let name = determine_share_name(&local_directory, requested_name)?;
        let initial_manifest = Manifest::empty(share_identity.share_id, now_ms);
        let scanned = scan_manifest(
            &local_directory,
            &initial_manifest,
            ClockState::new(),
            &endpoint_id,
            now_ms,
        )?;

        let config = ShareConfig {
            format_version: FORMAT_VERSION,
            share_id: share_identity.share_id,
            share_secret: share_identity.share_secret.clone(),
            name: name.clone(),
            local_directory: path_to_config_string(&local_directory)?,
            created_at_ms: now_ms,
            initial_peers: vec![endpoint_id_string(&endpoint_id)],
            initial_sync_complete: true,
        };
        let peers = KnownPeers::empty();
        let mut runtime = RuntimeStatus::stopped(now_ms);
        runtime.last_scan_at_ms = Some(now_ms);
        runtime.pending_updates = scanned.changes;

        // Publish all per-share state together, with the HLC already advanced before its
        // manifest is made visible.
        self.paths.create_share_state(
            &config,
            &scanned.manifest,
            &scanned.clock,
            &peers,
            &runtime,
        )?;

        let ticket = ShareTicket::new(
            share_identity.share_id,
            share_identity.share_secret,
            vec![endpoint_id],
        )?
        .encode()?;
        Ok(InitResult {
            name,
            share_id: config.share_id,
            local_directory,
            endpoint_id,
            ticket,
            files: scanned.files,
        })
    }

    pub fn register_join(
        &self,
        ticket_text: &str,
        requested_directory: &Path,
    ) -> Result<JoinResult> {
        // Parse before creating a directory or any local application state.
        let ticket = ShareTicket::parse(ticket_text)?;
        let local_directory = normalize_local_directory(requested_directory)?;
        self.ensure_directory_isolated_from_data_root(&local_directory)?;
        let _registry_lock = self.paths.acquire_registry_lock()?;
        if self.paths.share_exists(ticket.share_id) {
            bail!(
                "share {} is already registered on this device",
                ticket.share_id
            );
        }
        if let Some(existing_share_id) = self.find_share_for_directory(&local_directory)? {
            bail!(
                "local directory {} is already registered by share {}",
                local_directory.display(),
                existing_share_id
            );
        }

        let identity = identity::load_or_create(&self.paths)?;
        let endpoint_id = identity.endpoint_id();
        let now_ms = current_time_ms();
        let name = determine_share_name(&local_directory, None)?;
        let mut initial_peer_strings: Vec<String> = ticket
            .initial_peers
            .iter()
            .map(endpoint_id_string)
            .collect();
        initial_peer_strings.sort_unstable();
        initial_peer_strings.dedup();
        let peers = KnownPeers {
            format_version: FORMAT_VERSION,
            peers: initial_peer_strings
                .iter()
                .map(|endpoint_id| PeerRecord {
                    endpoint_id: endpoint_id.clone(),
                    added_at_ms: now_ms,
                    last_seen_at_ms: None,
                })
                .collect(),
        };
        peers.validate()?;
        let config = ShareConfig {
            format_version: FORMAT_VERSION,
            share_id: ticket.share_id,
            share_secret: ticket.share_secret.clone(),
            name: name.clone(),
            local_directory: path_to_config_string(&local_directory)?,
            created_at_ms: now_ms,
            initial_peers: initial_peer_strings,
            // The manifest remains empty until a remote manifest has been fetched. This stops old
            // files that happened to be in a join target from being published prematurely.
            initial_sync_complete: false,
        };
        let manifest = Manifest::empty(ticket.share_id, now_ms);
        let mut runtime = RuntimeStatus::stopped(now_ms);
        runtime.state = RuntimeState::WaitingForPeers;
        runtime.health = SyncHealth::Offline;

        self.paths
            .create_share_state(&config, &manifest, &ClockState::new(), &peers, &runtime)?;

        Ok(JoinResult {
            name,
            share_id: ticket.share_id,
            local_directory,
            endpoint_id,
            initial_peers: ticket.initial_peers,
            initial_sync_status: network::InitialSyncStatus::Offline,
        })
    }

    pub async fn join(&self, ticket_text: &str, requested_directory: &Path) -> Result<JoinResult> {
        let mut result = self.register_join(ticket_text, requested_directory)?;
        let identity = identity::load_or_create(&self.paths)?;
        // An unavailable peer is an expected join state. The durable registration made above is
        // retained and run will continue retrying without requiring the ticket again. State and
        // lifecycle errors propagate so a removed registration is never reported as successful.
        result.initial_sync_status =
            network::attempt_initial_sync(self.paths.clone(), identity, result.share_id).await?;
        Ok(result)
    }

    pub async fn run(&self, selector: Option<&str>, once: bool) -> Result<RunCommandResult> {
        let registry_lock = self.paths.acquire_registry_lock()?;
        let share_ids = match selector {
            Some(selector) => vec![self.resolve_share_selector(selector)?],
            None => self.paths.list_share_ids()?,
        };
        if share_ids.is_empty() {
            return Ok(RunCommandResult { shares_started: 0 });
        }
        for share_id in &share_ids {
            let config = self.paths.load_config(*share_id)?;
            self.ensure_directory_isolated_from_data_root(&config_directory(&config)?)?;
        }
        let Some(_device_lock) = self.paths.try_acquire_device_run_lock()? else {
            bail!("syncbox run is already active for this device");
        };
        let mut ordered_share_ids = share_ids;
        ordered_share_ids.sort_unstable();
        let mut share_locks = Vec::with_capacity(ordered_share_ids.len());
        for share_id in &ordered_share_ids {
            let Some(lock) = self.paths.try_acquire_share_lock(*share_id)? else {
                bail!("share {share_id} is already in use by another Syncbox process");
            };
            share_locks.push(lock);
        }
        drop(registry_lock);
        let identity = identity::load_or_create(&self.paths)?;
        network::run(
            self.paths.clone(),
            identity,
            ordered_share_ids.clone(),
            once,
        )
        .await?;
        drop(share_locks);
        Ok(RunCommandResult {
            shares_started: ordered_share_ids.len(),
        })
    }

    pub fn remove(&self, selector: &str) -> Result<RemoveCommandResult> {
        let _registry_lock = self.paths.acquire_registry_lock()?;
        let share_id = self.resolve_share_selector(selector)?;
        let Some(_share_lock) = self.paths.try_acquire_share_lock(share_id)? else {
            bail!(
                "share {share_id} is currently in use by another Syncbox process; stop it before removing the share"
            );
        };

        if selector != share_id.to_string()
            && let Err(error) = self.validate_share_state(share_id)
        {
            bail!(
                "share {share_id} has incomplete or invalid local state; use its full 64-character Share ID to remove it: {error:#}"
            );
        }
        self.paths.remove_share_state(share_id)?;
        Ok(RemoveCommandResult { share_id })
    }

    pub fn scan(&self, selector: &str) -> Result<ScanCommandResult> {
        let share_id = self.resolve_share_selector(selector)?;
        let Some(_share_lock) = self.paths.try_acquire_share_lock(share_id)? else {
            bail!("share {share_id} is currently in use by syncbox run");
        };
        let config = self.paths.load_config(share_id)?;
        if !config.initial_sync_complete {
            bail!(
                "share {share_id} has not received its first remote manifest; run syncbox run first"
            );
        }
        let identity = identity::load_or_create(&self.paths)?;
        let root = config_directory(&config)?;
        self.ensure_directory_isolated_from_data_root(&root)?;
        let manifest = self.paths.load_manifest(share_id)?;
        let clock = self.paths.load_clock(share_id)?;
        let now_ms = current_time_ms();
        let scanned = scan_manifest(&root, &manifest, clock, &identity.endpoint_id(), now_ms)?;
        if scanned.changes > 0 {
            self.paths.save_clock(share_id, &scanned.clock)?;
        }
        if scanned.manifest_changed {
            self.paths.save_manifest(&scanned.manifest)?;
        }

        let mut runtime = self
            .paths
            .load_runtime_status(share_id)?
            .unwrap_or_else(|| RuntimeStatus::stopped(now_ms));
        runtime.last_scan_at_ms = Some(now_ms);
        runtime.heartbeat_at_ms = now_ms;
        if scanned.changes > 0 {
            runtime.pending_updates = scanned.changes;
        }
        if runtime.process_id == 0 {
            runtime.state = RuntimeState::Stopped;
        }
        self.paths.save_runtime_status(share_id, &runtime)?;

        Ok(ScanCommandResult {
            share_id,
            files: scanned.files,
            tombstones: scanned.tombstones,
            changed: scanned.changed,
        })
    }

    pub fn ticket(&self, selector: &str) -> Result<TicketResult> {
        let share_id = self.resolve_share_selector(selector)?;
        let config = self.paths.load_config(share_id)?;
        let initial_peers = config
            .initial_peers
            .iter()
            .map(|peer| parse_endpoint_id(peer))
            .collect::<Result<Vec<_>>>()?;
        let ticket =
            ShareTicket::new(config.share_id, config.share_secret, initial_peers)?.encode()?;
        Ok(TicketResult { share_id, ticket })
    }

    pub fn generate_workspace_ticket(&self) -> Result<GeneratedTicket> {
        let endpoint_id = self.device_id()?;
        let identity = ShareIdentity::random();
        let ticket = ShareTicket::new(identity.share_id, identity.share_secret, vec![endpoint_id])?
            .encode()?;
        Ok(GeneratedTicket {
            share_id: identity.share_id,
            endpoint_id,
            ticket,
        })
    }

    pub fn all_share_ids(&self) -> Result<Vec<ShareId>> {
        self.paths.list_share_ids()
    }

    fn validate_share_state(&self, share_id: ShareId) -> Result<()> {
        self.paths.load_config(share_id)?;
        self.paths.load_manifest(share_id)?;
        self.paths.load_clock(share_id)?;
        self.paths.load_known_peers(share_id)?;
        self.paths.load_runtime_status(share_id)?;
        Ok(())
    }

    pub fn resolve_share_selector(&self, selector: &str) -> Result<ShareId> {
        let matches: Vec<_> = self
            .paths
            .list_share_ids()?
            .into_iter()
            .filter(|share_id| share_id.matches_prefix(selector))
            .collect();
        match matches.as_slice() {
            [] => bail!("share ID '{selector}' does not match a registered share"),
            [share_id] => Ok(*share_id),
            _ => {
                let collisions = matches
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("share ID prefix '{selector}' is ambiguous: {collisions}")
            }
        }
    }

    pub fn status(&self, selector: Option<&str>) -> Result<StatusReport> {
        let share_ids = match selector {
            Some(selector) => vec![self.resolve_share_selector(selector)?],
            None => self.paths.list_share_ids()?,
        };
        let existing_identity = identity::load_existing(&self.paths)?;
        if !share_ids.is_empty() && existing_identity.is_none() {
            bail!("registered shares exist but the global device identity is missing");
        }
        let endpoint_id =
            existing_identity.map(|identity| endpoint_id_string(&identity.endpoint_id()));
        let now_ms = current_time_ms();
        let mut shares = Vec::with_capacity(share_ids.len());
        let mut details = Vec::with_capacity(share_ids.len());
        for share_id in share_ids {
            let config = self.paths.load_config(share_id)?;
            let manifest = self.paths.load_manifest(share_id)?;
            let peers = self.paths.load_known_peers(share_id)?;
            let status = self.paths.load_runtime_status(share_id)?;
            let assessment = self.assess_runtime(share_id, status.as_ref(), now_ms)?;
            let stored = status.unwrap_or_else(|| RuntimeStatus::stopped(now_ms));
            let last_scan_at_ms = stored.last_scan_at_ms.or(Some(manifest.scanned_at_ms));
            let output = ShareStatus {
                share_id: share_id.to_string(),
                name: config.name.clone(),
                local_directory: config.local_directory,
                endpoint_id: endpoint_id.clone().unwrap_or_default(),
                runtime: assessment.runtime.as_str().to_owned(),
                health: stored.health.as_str().to_owned(),
                files: manifest.entries.len(),
                tombstones: manifest.tombstones.len(),
                known_peers: peers.peers.len(),
                connected_peers: if assessment.runtime == RuntimeState::Stopped {
                    0
                } else {
                    stored.connected_peers
                },
                pending_downloads: stored.pending_downloads,
                pending_updates: stored.pending_updates,
                last_local_scan: format_timestamp(last_scan_at_ms),
                last_remote_update: format_timestamp(stored.last_remote_update_at_ms),
                last_successful_sync: format_timestamp(stored.last_sync_at_ms),
                last_connection: format_timestamp(stored.last_connection_at_ms),
                last_error: stored.last_error,
            };
            details.push(StatusDetails {
                heartbeat_stale: assessment.heartbeat_stale,
                last_recorded_state: assessment.last_recorded_state,
                output: output.clone(),
            });
            shares.push(output);
        }
        Ok(StatusReport { shares, details })
    }

    fn assess_runtime(
        &self,
        share_id: ShareId,
        status: Option<&RuntimeStatus>,
        now_ms: u64,
    ) -> Result<RuntimeAssessment> {
        let lock_held = self.paths.share_lock_is_held(share_id)?;
        let Some(status) = status else {
            return Ok(RuntimeAssessment {
                runtime: RuntimeState::Stopped,
                heartbeat_stale: false,
                last_recorded_state: None,
            });
        };
        let heartbeat_stale =
            now_ms.saturating_sub(status.heartbeat_at_ms) > STATUS_HEARTBEAT_STALE_MS;
        let process_alive = process_alive(status.process_id);
        let active = lock_held && !heartbeat_stale && process_alive && status.process_id != 0;
        if active {
            Ok(RuntimeAssessment {
                runtime: status.state,
                heartbeat_stale: false,
                last_recorded_state: None,
            })
        } else {
            Ok(RuntimeAssessment {
                runtime: RuntimeState::Stopped,
                heartbeat_stale: heartbeat_stale && status.state != RuntimeState::Stopped,
                last_recorded_state: (status.state != RuntimeState::Stopped)
                    .then_some(status.state),
            })
        }
    }

    fn find_share_for_directory(&self, local_directory: &Path) -> Result<Option<ShareId>> {
        for share_id in self.paths.list_share_ids()? {
            let config = self.paths.load_config(share_id)?;
            let configured = PathBuf::from(&config.local_directory);
            let existing = if configured.exists() {
                fs::canonicalize(&configured).with_context(|| {
                    format!(
                        "unable to normalize registered directory {}",
                        configured.display()
                    )
                })?
            } else {
                configured
            };
            // Shares cannot overlap. Otherwise scanning a parent share could publish child-share
            // files or application state associated with a nested directory.
            if local_directory.starts_with(&existing) || existing.starts_with(local_directory) {
                return Ok(Some(share_id));
            }
        }
        Ok(None)
    }

    fn ensure_directory_isolated_from_data_root(&self, local_directory: &Path) -> Result<()> {
        // Resolve existing ancestors without creating application state. This prevents a data
        // directory configured inside a prospective share from ever being created there.
        let data_root = canonical_or_projected_path(self.paths.root()).with_context(|| {
            format!(
                "unable to normalize Syncbox application data directory {}",
                self.paths.root().display()
            )
        })?;
        if local_directory.starts_with(&data_root) || data_root.starts_with(local_directory) {
            bail!(
                "local directory {} overlaps the Syncbox application data directory {}; choose a different shared directory",
                local_directory.display(),
                data_root.display()
            );
        }
        Ok(())
    }

    fn new_unused_share_identity(&self) -> Result<ShareIdentity> {
        for _ in 0..16 {
            let identity = ShareIdentity::random();
            if !self.paths.share_exists(identity.share_id) {
                return Ok(identity);
            }
        }
        bail!("could not generate an unused share ID")
    }
}

#[derive(Clone, Debug)]
pub struct InitResult {
    pub name: String,
    pub share_id: ShareId,
    pub local_directory: PathBuf,
    pub endpoint_id: EndpointId,
    pub ticket: String,
    pub files: usize,
}

#[derive(Clone, Debug)]
pub struct JoinResult {
    pub name: String,
    pub share_id: ShareId,
    pub local_directory: PathBuf,
    pub endpoint_id: EndpointId,
    pub initial_peers: Vec<EndpointId>,
    pub initial_sync_status: network::InitialSyncStatus,
}

#[derive(Clone, Debug)]
pub struct RunCommandResult {
    pub shares_started: usize,
}

#[derive(Clone, Debug)]
pub struct RemoveCommandResult {
    pub share_id: ShareId,
}

#[derive(Clone, Debug)]
pub struct ScanCommandResult {
    pub share_id: ShareId,
    pub files: usize,
    pub tombstones: usize,
    pub changed: bool,
}

#[derive(Clone, Debug)]
pub struct TicketResult {
    pub share_id: ShareId,
    pub ticket: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedTicket {
    pub share_id: ShareId,
    pub endpoint_id: EndpointId,
    pub ticket: String,
}

#[derive(Clone, Serialize)]
pub struct ShareStatus {
    pub share_id: String,
    pub name: String,
    pub local_directory: String,
    pub endpoint_id: String,
    pub runtime: String,
    pub health: String,
    pub files: usize,
    pub tombstones: usize,
    pub known_peers: usize,
    pub connected_peers: usize,
    pub pending_downloads: usize,
    pub pending_updates: usize,
    pub last_local_scan: Option<String>,
    pub last_remote_update: Option<String>,
    pub last_successful_sync: Option<String>,
    pub last_connection: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct StatusReport {
    pub shares: Vec<ShareStatus>,
    #[serde(skip_serializing)]
    details: Vec<StatusDetails>,
}

#[derive(Clone)]
struct StatusDetails {
    heartbeat_stale: bool,
    last_recorded_state: Option<RuntimeState>,
    output: ShareStatus,
}

impl StatusReport {
    pub fn human_text(&self) -> String {
        if self.details.is_empty() {
            return "No shared directories registered\n".to_owned();
        }
        self.details
            .iter()
            .map(format_human_share_status)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

struct RuntimeAssessment {
    runtime: RuntimeState,
    heartbeat_stale: bool,
    last_recorded_state: Option<RuntimeState>,
}

fn canonical_or_projected_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("unable to determine the current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let mut missing_tail = Vec::new();
    let mut existing = normalized.as_path();
    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| anyhow!("path has no existing ancestor"))?;
        missing_tail.push(name.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| anyhow!("path has no existing ancestor"))?;
    }
    let mut resolved = fs::canonicalize(existing)
        .with_context(|| format!("unable to normalize path {}", existing.display()))?;
    for component in missing_tail.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn normalize_local_directory(requested_directory: &Path) -> Result<PathBuf> {
    if requested_directory.exists() {
        let metadata = fs::metadata(requested_directory).with_context(|| {
            format!(
                "unable to inspect local directory {}",
                requested_directory.display()
            )
        })?;
        if !metadata.is_dir() {
            bail!("{} is not a directory", requested_directory.display());
        }
    } else {
        fs::create_dir_all(requested_directory).with_context(|| {
            format!(
                "unable to create local directory {}",
                requested_directory.display()
            )
        })?;
    }
    let directory = fs::canonicalize(requested_directory).with_context(|| {
        format!(
            "unable to normalize local directory {}",
            requested_directory.display()
        )
    })?;
    if directory.to_str().is_none() {
        bail!("local directory path is not valid UTF-8");
    }
    Ok(directory)
}

fn path_to_config_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("local directory path is not valid UTF-8"))
}

fn config_directory(config: &ShareConfig) -> Result<PathBuf> {
    let path = PathBuf::from(&config.local_directory);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("unable to inspect local directory {}", path.display()))?;
    if !metadata.is_dir() {
        bail!(
            "registered local path {} is not a directory",
            path.display()
        );
    }
    fs::canonicalize(&path)
        .with_context(|| format!("unable to normalize local directory {}", path.display()))
}

fn determine_share_name(local_directory: &Path, requested_name: Option<&str>) -> Result<String> {
    let name = requested_name.map_or_else(
        || {
            local_directory
                .file_name()
                .and_then(|component| component.to_str())
                .filter(|component| !component.is_empty())
                .unwrap_or("share")
                .to_owned()
        },
        std::borrow::ToOwned::to_owned,
    );
    validate_share_name(&name)?;
    Ok(name)
}

fn format_timestamp(value: Option<u64>) -> Option<String> {
    value.and_then(|milliseconds| {
        i64::try_from(milliseconds)
            .ok()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
    })
}

fn format_human_share_status(details: &StatusDetails) -> String {
    let status = &details.output;
    let mut lines = vec![
        format!("Share: {}", status.name),
        format!("Share ID: {}", status.share_id),
        format!("Local directory: {}", status.local_directory),
        String::new(),
        format!("Runtime: {}", status.runtime),
        format!("Health: {}", status.health),
        String::new(),
        format!("Endpoint ID: {}", status.endpoint_id),
        format!("Files: {}", status.files),
        format!("Tombstones: {}", status.tombstones),
        String::new(),
        format!("Known peers: {}", status.known_peers),
        format!("Connected peers: {}", status.connected_peers),
        String::new(),
        format!("Pending downloads: {}", status.pending_downloads),
        format!("Pending updates: {}", status.pending_updates),
        String::new(),
        format!(
            "Last local scan: {}",
            display_optional(status.last_local_scan.as_deref())
        ),
        format!(
            "Last remote update: {}",
            display_optional(status.last_remote_update.as_deref())
        ),
        format!(
            "Last successful sync: {}",
            display_optional(status.last_successful_sync.as_deref())
        ),
        format!(
            "Last connection: {}",
            display_optional(status.last_connection.as_deref())
        ),
        format!(
            "Last error: {}",
            display_optional(status.last_error.as_deref())
        ),
    ];
    if let Some(state) = details.last_recorded_state {
        lines.push(format!("Last recorded state: {state}"));
    }
    if details.heartbeat_stale {
        lines.push("Status heartbeat is stale".to_owned());
    }
    lines.push(String::new());
    lines.join("\n")
}

fn display_optional(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

#[cfg(target_os = "linux")]
fn process_alive(process_id: u32) -> bool {
    if process_id == 0 {
        return false;
    }
    Path::new("/proc").join(process_id.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn process_alive(process_id: u32) -> bool {
    if process_id == 0 {
        false
    } else {
        // The lock plus a fresh heartbeat remains authoritative on platforms where the process
        // table is not exposed through a portable standard-library API.
        true
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::storage::DataPaths;

    #[test]
    fn init_registers_state_outside_the_shared_directory() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("settings.txt"), "value").unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&root, Some("config")).unwrap();
        assert!(!root.join(".syncbox").exists());
        assert!(app.paths().share_config(result.share_id).exists());
        assert!(app.paths().share_manifest(result.share_id).exists());
        assert!(app.paths().share_clock(result.share_id).exists());
        assert!(app.paths().share_known_peers(result.share_id).exists());
        assert!(app.paths().share_runtime_status(result.share_id).exists());
    }

    #[test]
    fn remove_unregisters_share_without_deleting_local_files() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("keep.txt"), "keep").unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&root, None).unwrap();
        let share_id = result.share_id.to_string();

        let removed = app.remove(&share_id[..8]).unwrap();

        assert_eq!(removed.share_id, result.share_id);
        assert!(!app.paths().share_dir(result.share_id).exists());
        assert_eq!(fs::read_to_string(root.join("keep.txt")).unwrap(), "keep");
        assert_eq!(app.all_share_ids().unwrap(), Vec::<ShareId>::new());
    }

    #[test]
    fn remove_requires_full_id_for_invalid_state() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&root, None).unwrap();
        let share_id = result.share_id.to_string();
        fs::write(app.paths().share_manifest(result.share_id), "invalid").unwrap();

        let error = app.remove(&share_id[..8]).unwrap_err().to_string();
        assert!(error.contains("use its full 64-character Share ID"));
        assert!(app.paths().share_dir(result.share_id).is_dir());

        app.remove(&share_id).unwrap();
        assert!(!app.paths().share_dir(result.share_id).exists());
        assert!(root.is_dir());
    }

    #[test]
    fn remove_rejects_a_share_that_is_in_use() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&root, None).unwrap();
        let _lock = app.paths().acquire_share_lock(result.share_id).unwrap();

        let error = app.remove(&result.share_id.to_string()).unwrap_err();

        assert!(error.to_string().contains("currently in use"));
        assert!(app.paths().share_dir(result.share_id).is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn initial_sync_propagates_removed_share_state_errors() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&root, None).unwrap();
        let identity = identity::load_or_create(app.paths()).unwrap();
        app.paths().remove_share_state(result.share_id).unwrap();

        let error = network::attempt_initial_sync(app.paths().clone(), identity, result.share_id)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("unable to inspect"));
    }

    #[test]
    fn same_directory_cannot_be_registered_twice() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        app.init(&root, None).unwrap();
        let error = app.init(&root, None).unwrap_err();
        assert!(error.to_string().contains("already registered"));
    }

    #[test]
    fn nested_directories_cannot_be_registered_as_separate_shares() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("workspace");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        app.init(&root, None).unwrap();
        let error = app.init(&nested, None).unwrap_err();
        assert!(error.to_string().contains("already registered"));
    }

    #[test]
    fn application_data_directory_cannot_be_a_share() {
        let temporary = TempDir::new().unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let data_root = app.paths().root().to_path_buf();
        let error = app.init(&data_root, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("overlaps the Syncbox application data directory")
        );
        assert!(!app.paths().identity_dir().exists());
        assert!(!app.paths().shares_dir().exists());
    }

    #[test]
    fn data_directory_inside_a_share_is_rejected_before_state_is_created() {
        let temporary = TempDir::new().unwrap();
        let shared_directory = temporary.path().join("workspace");
        fs::create_dir_all(&shared_directory).unwrap();
        let app = App::with_paths(DataPaths::from_root(shared_directory.join("state")));
        let error = app.init(&shared_directory, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("overlaps the Syncbox application data directory")
        );
        assert!(!shared_directory.join("state/identity").exists());
        assert!(!shared_directory.join("state/shares").exists());
    }

    #[test]
    fn multiple_shares_use_one_device_identity_and_independent_state() {
        let temporary = TempDir::new().unwrap();
        let first_directory = temporary.path().join("first");
        let second_directory = temporary.path().join("second");
        fs::create_dir_all(&first_directory).unwrap();
        fs::create_dir_all(&second_directory).unwrap();
        fs::write(first_directory.join("one.txt"), "one").unwrap();
        fs::write(second_directory.join("two.txt"), "two").unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let first = app.init(&first_directory, Some("first")).unwrap();
        let second = app.init(&second_directory, Some("second")).unwrap();
        assert_ne!(first.share_id, second.share_id);
        assert_eq!(first.endpoint_id, second.endpoint_id);
        let report = app.status(None).unwrap();
        assert_eq!(report.shares.len(), 2);
        assert!(app.paths().share_manifest(first.share_id).exists());
        assert!(app.paths().share_manifest(second.share_id).exists());
    }

    #[test]
    fn stale_runtime_status_is_reported_as_stopped() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("workspace");
        fs::create_dir_all(&directory).unwrap();
        let app = App::with_paths(DataPaths::from_root(temporary.path().join("data")));
        let result = app.init(&directory, None).unwrap();
        let _lock = app.paths().acquire_share_lock(result.share_id).unwrap();
        let mut runtime = RuntimeStatus::stopped(0);
        runtime.process_id = std::process::id();
        runtime.state = RuntimeState::Running;
        runtime.heartbeat_at_ms = 0;
        app.paths()
            .save_runtime_status(result.share_id, &runtime)
            .unwrap();
        let report = app.status(Some(&result.share_id.to_string())).unwrap();
        assert_eq!(report.shares[0].runtime, "stopped");
    }
}
