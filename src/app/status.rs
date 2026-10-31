//! Runtime assessment and status reporting.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::{manifest::Manifest, types::RuntimeState};

pub use super::directory::process_alive;

#[cfg(windows)]
pub(crate) const fn unsupported_symlink_count(manifest: &Manifest) -> usize {
    manifest.symlinks.len()
}

#[cfg(not(windows))]
pub const fn unsupported_symlink_count(_manifest: &Manifest) -> usize {
    0
}

pub const STATUS_HEARTBEAT_STALE_MS: u64 = 15_000;

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
    pub unsupported_items: usize,
    pub last_local_scan: Option<String>,
    pub last_remote_update: Option<String>,
    pub last_successful_sync: Option<String>,
    pub last_connection: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct StatusDetails {
    pub(crate) heartbeat_stale: bool,
    pub(crate) last_recorded_state: Option<RuntimeState>,
    pub(crate) output: ShareStatus,
}
pub struct RuntimeAssessment {
    pub(crate) runtime: RuntimeState,
    pub(crate) heartbeat_stale: bool,
    pub(crate) last_recorded_state: Option<RuntimeState>,
}

pub fn format_timestamp(value: Option<u64>) -> Option<String> {
    value.and_then(|milliseconds| {
        i64::try_from(milliseconds)
            .ok()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
    })
}

pub fn format_human_share_status(details: &StatusDetails) -> String {
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
        format!("Unsupported items: {}", status.unsupported_items),
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

pub fn display_optional(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

#[derive(Clone, Serialize)]
pub struct StatusReport {
    pub shares: Vec<ShareStatus>,
    #[serde(skip_serializing)]
    pub(crate) details: Vec<StatusDetails>,
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
