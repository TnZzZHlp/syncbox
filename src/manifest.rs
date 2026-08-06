use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use walkdir::WalkDir;

use crate::types::{ClockState, FORMAT_VERSION, HlcTimestamp, ShareId};

pub const MAX_MANIFEST_ENTRIES: usize = 100_000;
const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u16,
    pub share_id: ShareId,
    pub scanned_at_ms: u64,
    pub entries: BTreeMap<String, ManifestEntry>,
    pub tombstones: BTreeMap<String, Tombstone>,
}

impl Manifest {
    pub const fn empty(share_id: ShareId, now_ms: u64) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            share_id,
            scanned_at_ms: now_ms,
            entries: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    pub fn validate(&self, expected_share_id: ShareId) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            bail!(
                "unsupported manifest format version {}",
                self.format_version
            );
        }
        if self.share_id != expected_share_id {
            bail!("manifest share ID does not match its directory");
        }
        let total = self
            .entries
            .len()
            .checked_add(self.tombstones.len())
            .ok_or_else(|| anyhow!("manifest entry count overflow"))?;
        if total > MAX_MANIFEST_ENTRIES {
            bail!("manifest exceeds the maximum supported entry count");
        }
        for (path, entry) in &self.entries {
            validate_manifest_path(path)?;
            entry.validate()?;
            if self.tombstones.contains_key(path) {
                bail!("manifest has both a file and a tombstone for {path}");
            }
        }
        for (path, tombstone) in &self.tombstones {
            validate_manifest_path(path)?;
            tombstone.validate()?;
        }
        Ok(())
    }

    pub fn record(&self, path: &str) -> Option<ManifestRecordRef<'_>> {
        if let Some(entry) = self.entries.get(path) {
            return Some(ManifestRecordRef::File(entry));
        }
        self.tombstones.get(path).map(ManifestRecordRef::Tombstone)
    }

    pub fn all_paths(&self) -> BTreeSet<String> {
        self.entries
            .keys()
            .chain(self.tombstones.keys())
            .cloned()
            .collect()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub size: u64,
    pub modified_at_ns: u64,
    pub sha256: String,
    pub version: HlcTimestamp,
}

impl ManifestEntry {
    pub fn validate(&self) -> Result<()> {
        if self.sha256.len() != 64
            || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.sha256.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            bail!("manifest file hash must be 64 lowercase hexadecimal characters");
        }
        validate_timestamp(&self.version)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    pub version: HlcTimestamp,
}

impl Tombstone {
    pub fn validate(&self) -> Result<()> {
        validate_timestamp(&self.version)
    }
}

fn validate_timestamp(timestamp: &HlcTimestamp) -> Result<()> {
    EndpointId::from_bytes(&timestamp.author)
        .map_err(|_| anyhow!("manifest has an invalid HLC author"))?;
    Ok(())
}

#[derive(Clone, Copy)]
pub enum ManifestRecordRef<'a> {
    File(&'a ManifestEntry),
    Tombstone(&'a Tombstone),
}

impl ManifestRecordRef<'_> {
    pub const fn version(self) -> HlcTimestamp {
        match self {
            Self::File(entry) => entry.version,
            Self::Tombstone(tombstone) => tombstone.version,
        }
    }

    pub const fn is_tombstone(self) -> bool {
        matches!(self, Self::Tombstone(_))
    }
}

#[derive(Clone)]
pub enum ManifestRecord {
    File(ManifestEntry),
    Tombstone(Tombstone),
}

impl ManifestRecord {
    pub const fn version(&self) -> HlcTimestamp {
        match self {
            Self::File(entry) => entry.version,
            Self::Tombstone(tombstone) => tombstone.version,
        }
    }
}

pub struct ScanResult {
    pub manifest: Manifest,
    pub clock: ClockState,
    pub files: usize,
    pub tombstones: usize,
    pub changes: usize,
    pub changed: bool,
}

/// Scans a root directory and creates a manifest. State is returned rather than persisted so the
/// caller can persist the HLC before the manifest.
pub fn scan_manifest(
    root: &Path,
    previous: &Manifest,
    mut clock: ClockState,
    endpoint_id: &EndpointId,
    now_ms: u64,
) -> Result<ScanResult> {
    previous.validate(previous.share_id)?;
    clock.validate()?;
    let discovered = discover_files(root)?;
    let mut entries = BTreeMap::new();
    let mut tombstones = previous.tombstones.clone();
    let mut changes = 0_usize;

    for (path, discovered_file) in &discovered {
        let old_entry = previous.entries.get(path);
        let unchanged = old_entry.is_some_and(|entry| {
            entry.size == discovered_file.size && entry.sha256 == discovered_file.sha256
        });
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            old_entry.clone()
        } else {
            changes = changes.saturating_add(1);
            let version = clock.tick(now_ms, *endpoint_id.as_bytes())?;
            ManifestEntry {
                size: discovered_file.size,
                modified_at_ns: discovered_file.modified_at_ns,
                sha256: discovered_file.sha256.clone(),
                version,
            }
        };
        let _ = tombstones.remove(path);
        entries.insert(path.clone(), entry);
    }

    for path in previous.entries.keys() {
        if !discovered.contains_key(path) {
            changes = changes.saturating_add(1);
            tombstones.insert(
                path.clone(),
                Tombstone {
                    version: clock.tick(now_ms, *endpoint_id.as_bytes())?,
                },
            );
        }
    }

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        share_id: previous.share_id,
        scanned_at_ms: now_ms,
        entries,
        tombstones,
    };
    manifest.validate(previous.share_id)?;
    Ok(ScanResult {
        files: manifest.entries.len(),
        tombstones: manifest.tombstones.len(),
        manifest,
        clock,
        changes,
        changed: changes > 0,
    })
}

#[derive(Clone)]
struct DiscoveredFile {
    size: u64,
    modified_at_ns: u64,
    sha256: String,
}

fn discover_files(root: &Path) -> Result<BTreeMap<String, DiscoveredFile>> {
    let metadata = fs::metadata(root)
        .with_context(|| format!("unable to inspect local directory {}", root.display()))?;
    if !metadata.is_dir() {
        bail!("local path {} is not a directory", root.display());
    }

    let mut discovered = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry =
            entry.with_context(|| format!("unable to scan local directory {}", root.display()))?;
        if entry.path() == root {
            continue;
        }
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if discovered.len() >= MAX_MANIFEST_ENTRIES {
            bail!("local directory exceeds the maximum supported file count");
        }
        let path = relative_manifest_path(root, entry.path())?;
        let metadata = entry
            .metadata()
            .with_context(|| format!("unable to inspect local file {}", entry.path().display()))?;
        let (size, modified_at_ns, sha256) = hash_stable_file(entry.path(), &metadata)?;
        discovered.insert(
            path,
            DiscoveredFile {
                size,
                modified_at_ns,
                sha256,
            },
        );
    }
    Ok(discovered)
}

fn hash_stable_file(path: &Path, expected_metadata: &fs::Metadata) -> Result<(u64, u64, String)> {
    let first_size = expected_metadata.len();
    let first_modified = modified_at_ns(expected_metadata);
    for _ in 0..3 {
        let mut file = File::open(path)
            .with_context(|| format!("unable to open local file {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; HASH_BUFFER_SIZE].into_boxed_slice();
        loop {
            let count = file
                .read(&mut buffer)
                .with_context(|| format!("unable to read local file {}", path.display()))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let after = file
            .metadata()
            .with_context(|| format!("unable to inspect local file {}", path.display()))?;
        if after.len() == first_size && modified_at_ns(&after) == first_modified {
            return Ok((first_size, first_modified, hex::encode(hasher.finalize())));
        }
    }
    bail!(
        "local file changed while it was being scanned: {}",
        path.display()
    )
}

fn modified_at_ns(metadata: &fs::Metadata) -> u64 {
    let duration = metadata
        .modified()
        .unwrap_or(UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = duration.as_nanos();
    u64::try_from(nanos.min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
}

pub fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn validate_manifest_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.contains('\\') || value.contains('\0') {
        bail!("manifest path is invalid");
    }
    let path = Path::new(value);
    if path.is_absolute() {
        bail!("manifest path must be relative");
    }
    let components = path.components();
    let mut count = 0_usize;
    for component in components {
        match component {
            Component::Normal(component) => {
                if component.is_empty() || component.to_str().is_none() {
                    bail!("manifest path contains an invalid component");
                }
                count += 1;
            }
            _ => bail!("manifest path contains an unsafe component"),
        }
    }
    if count == 0 {
        bail!("manifest path is empty");
    }
    Ok(())
}

pub fn path_for_manifest(root: &Path, manifest_path: &str) -> Result<PathBuf> {
    validate_manifest_path(manifest_path)?;
    let mut path = root.to_path_buf();
    for component in manifest_path.split('/') {
        path.push(component);
    }
    Ok(path)
}

fn relative_manifest_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("scanned path {} is outside its root", path.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| anyhow!("local file name is not valid UTF-8"))?;
                if component.is_empty() || component.contains('\\') || component.contains('/') {
                    bail!("local file name cannot be represented safely in a manifest");
                }
                parts.push(component);
            }
            _ => bail!("local file path cannot be represented safely in a manifest"),
        }
    }
    let value = parts.join("/");
    validate_manifest_path(&value)?;
    Ok(value)
}

pub fn merge_manifests(local: &Manifest, remote: &Manifest, now_ms: u64) -> Result<Manifest> {
    local.validate(local.share_id)?;
    remote.validate(local.share_id)?;
    let mut merged = Manifest::empty(local.share_id, now_ms);
    for path in local.all_paths().union(&remote.all_paths()) {
        let local_record = local.record(path);
        let remote_record = remote.record(path);
        let selected = select_record(local_record, remote_record);
        match selected {
            Some(ManifestRecordRef::File(entry)) => {
                merged.entries.insert(path.clone(), entry.clone());
            }
            Some(ManifestRecordRef::Tombstone(tombstone)) => {
                merged.tombstones.insert(path.clone(), tombstone.clone());
            }
            None => {}
        }
    }
    merged.validate(local.share_id)?;
    Ok(merged)
}

pub fn select_record<'a>(
    left: Option<ManifestRecordRef<'a>>,
    right: Option<ManifestRecordRef<'a>>,
) -> Option<ManifestRecordRef<'a>> {
    match (left, right) {
        (None, record) | (record, None) => record,
        (Some(left), Some(right)) => match left.version().cmp(&right.version()) {
            std::cmp::Ordering::Less => Some(right),
            // A tombstone wins a tie so deletion is conservative under malformed equal clocks.
            std::cmp::Ordering::Equal if right.is_tombstone() => Some(right),
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => Some(left),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use iroh::SecretKey;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn scanner_preserves_versions_for_unchanged_files() {
        let temporary = TempDir::new().unwrap();
        fs::write(temporary.path().join("config.txt"), "one").unwrap();
        let share_id = ShareId([1; 32]);
        let endpoint = SecretKey::from_bytes(&[2; 32]).public();
        let first = scan_manifest(
            temporary.path(),
            &Manifest::empty(share_id, 1),
            ClockState::new(),
            &endpoint,
            2,
        )
        .unwrap();
        let second =
            scan_manifest(temporary.path(), &first.manifest, first.clock, &endpoint, 3).unwrap();
        assert_eq!(
            first.manifest.entries["config.txt"].version,
            second.manifest.entries["config.txt"].version
        );
    }

    #[test]
    fn unsafe_manifest_paths_are_rejected() {
        for path in ["", "../secret", "/secret", "a\\b", "a/../../b"] {
            assert!(validate_manifest_path(path).is_err(), "{path}");
        }
    }
}
