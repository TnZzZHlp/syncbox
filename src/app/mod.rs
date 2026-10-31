//! Command workflows and status reporting.
//!
//! - `App`: durable operations over a `DataPaths` root (init, join, remove, scan, status, tickets).
//! - `directory`: shared-directory normalization, isolation, and path helpers.
//! - `status`: runtime assessment, JSON status records, and human-readable formatting.

use std::{
    fs,
    path::{Path, PathBuf},
};

use iroh::EndpointId;

use anyhow::{Context, Result, bail};

use crate::{
    identity,
    manifest::{Manifest, current_time_ms, scan_manifest, scan_manifest_cached_after_validation},
    network,
    storage::DataPaths,
    ticket::ShareTicket,
    types::{
        ClockState, FORMAT_VERSION, KnownPeers, PeerRecord, RuntimeState, RuntimeStatus,
        ShareConfig, ShareId, ShareIdentity, SyncHealth, endpoint_id_string, parse_endpoint_id,
    },
};

mod directory;
mod status;

pub use status::{STATUS_HEARTBEAT_STALE_MS, ShareStatus, StatusReport};

use directory::{
    canonical_or_projected_path, config_directory, determine_share_name, normalize_local_directory,
    path_to_config_string,
};
use status::{
    RuntimeAssessment, StatusDetails, format_timestamp, process_alive, unsupported_symlink_count,
};

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
        let scanned = scan_manifest_cached_after_validation(
            &root,
            &manifest,
            clock,
            &identity.endpoint_id(),
            now_ms,
        )?;
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
            let unsupported_items = unsupported_symlink_count(&manifest);
            let runtime = if unsupported_items > 0 && assessment.runtime != RuntimeState::Stopped {
                RuntimeState::Degraded
            } else {
                assessment.runtime
            };
            let health = if unsupported_items > 0 {
                SyncHealth::Error
            } else {
                stored.health
            };
            let last_error = if unsupported_items > 0 {
                Some("symbolic links are unsupported on Windows".to_owned())
            } else {
                stored.last_error
            };
            let output = ShareStatus {
                share_id: share_id.to_string(),
                name: config.name.clone(),
                local_directory: config.local_directory,
                endpoint_id: endpoint_id.clone().unwrap_or_default(),
                runtime: runtime.as_str().to_owned(),
                health: health.as_str().to_owned(),
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
                unsupported_items,
                last_local_scan: format_timestamp(last_scan_at_ms),
                last_remote_update: format_timestamp(stored.last_remote_update_at_ms),
                last_successful_sync: format_timestamp(stored.last_sync_at_ms),
                last_connection: format_timestamp(stored.last_connection_at_ms),
                last_error,
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

#[cfg(test)]
mod tests;
