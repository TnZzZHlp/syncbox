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

use crate::types::{ClockState, HlcTimestamp, ShareId};

pub const MAX_MANIFEST_ENTRIES: usize = 100_000;
pub const MANIFEST_FORMAT_VERSION: u16 = 3;
const PREVIOUS_MANIFEST_FORMAT_VERSION: u16 = 2;
const LEGACY_MANIFEST_FORMAT_VERSION: u16 = 1;
const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u16,
    pub share_id: ShareId,
    pub scanned_at_ms: u64,
    pub entries: BTreeMap<String, ManifestEntry>,
    #[serde(default)]
    pub directories: BTreeMap<String, DirectoryEntry>,
    #[serde(default)]
    pub symlinks: BTreeMap<String, SymlinkEntry>,
    pub tombstones: BTreeMap<String, Tombstone>,
}

impl Manifest {
    pub const fn empty(share_id: ShareId, now_ms: u64) -> Self {
        Self {
            format_version: MANIFEST_FORMAT_VERSION,
            share_id,
            scanned_at_ms: now_ms,
            entries: BTreeMap::new(),
            directories: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    pub fn validate(&self, expected_share_id: ShareId) -> Result<()> {
        if !matches!(
            self.format_version,
            LEGACY_MANIFEST_FORMAT_VERSION
                | PREVIOUS_MANIFEST_FORMAT_VERSION
                | MANIFEST_FORMAT_VERSION
        ) {
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
            .checked_add(self.directories.len())
            .and_then(|total| total.checked_add(self.symlinks.len()))
            .and_then(|total| total.checked_add(self.tombstones.len()))
            .ok_or_else(|| anyhow!("manifest entry count overflow"))?;
        if total > MAX_MANIFEST_ENTRIES {
            bail!("manifest exceeds the maximum supported entry count");
        }
        for (path, entry) in &self.entries {
            validate_manifest_path(path)?;
            entry.validate()?;
            if self.directories.contains_key(path) {
                bail!("manifest has both a file and a directory for {path}");
            }
            if self.tombstones.contains_key(path) {
                bail!("manifest has both an entry and a tombstone for {path}");
            }
        }
        for (path, entry) in &self.directories {
            validate_manifest_path(path)?;
            entry.validate()?;
            if self.tombstones.contains_key(path) {
                bail!("manifest has both an entry and a tombstone for {path}");
            }
        }
        for (path, entry) in &self.symlinks {
            validate_manifest_path(path)?;
            entry.validate()?;
            if self.entries.contains_key(path) || self.directories.contains_key(path) {
                bail!("manifest has both a live path and a symlink for {path}");
            }
            if self.tombstones.contains_key(path) {
                bail!("manifest has both an entry and a tombstone for {path}");
            }
        }
        for (path, tombstone) in &self.tombstones {
            validate_manifest_path(path)?;
            tombstone.validate()?;
        }
        validate_manifest_hierarchy(self)?;
        Ok(())
    }

    pub fn record(&self, path: &str) -> Option<ManifestRecordRef<'_>> {
        if let Some(entry) = self.entries.get(path) {
            return Some(ManifestRecordRef::File(entry));
        }
        if let Some(entry) = self.directories.get(path) {
            return Some(ManifestRecordRef::Directory(entry));
        }
        if let Some(entry) = self.symlinks.get(path) {
            return Some(ManifestRecordRef::Symlink(entry));
        }
        self.tombstones.get(path).map(ManifestRecordRef::Tombstone)
    }

    pub fn all_paths(&self) -> BTreeSet<String> {
        self.entries
            .keys()
            .chain(self.directories.keys())
            .chain(self.symlinks.keys())
            .chain(self.tombstones.keys())
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub size: u64,
    pub modified_at_ns: u64,
    pub sha256: String,
    #[serde(default)]
    pub permissions: Option<u16>,
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
        validate_permissions(self.permissions)?;
        validate_timestamp(&self.version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    #[serde(default)]
    pub permissions: Option<u16>,
    pub version: HlcTimestamp,
}

impl DirectoryEntry {
    pub fn validate(&self) -> Result<()> {
        validate_permissions(self.permissions)?;
        validate_timestamp(&self.version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymlinkEntry {
    pub target: String,
    pub version: HlcTimestamp,
}

impl SymlinkEntry {
    pub fn validate(&self) -> Result<()> {
        validate_symlink_target(&self.target)?;
        validate_timestamp(&self.version)
    }
}

fn validate_symlink_target(target: &str) -> Result<()> {
    if target.is_empty() || target.len() > 4096 || target.contains('\0') {
        bail!("manifest symlink target is invalid");
    }
    Ok(())
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

fn validate_permissions(permissions: Option<u16>) -> Result<()> {
    if permissions.is_some_and(|permissions| permissions > 0o7777) {
        bail!("manifest permissions contain unsupported bits");
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub enum ManifestRecordRef<'a> {
    File(&'a ManifestEntry),
    Directory(&'a DirectoryEntry),
    Symlink(&'a SymlinkEntry),
    Tombstone(&'a Tombstone),
}

impl ManifestRecordRef<'_> {
    pub const fn version(self) -> HlcTimestamp {
        match self {
            Self::File(entry) => entry.version,
            Self::Directory(entry) => entry.version,
            Self::Symlink(entry) => entry.version,
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
    Directory(DirectoryEntry),
    Symlink(SymlinkEntry),
    Tombstone(Tombstone),
}

impl ManifestRecord {
    pub const fn version(&self) -> HlcTimestamp {
        match self {
            Self::File(entry) => entry.version,
            Self::Directory(entry) => entry.version,
            Self::Symlink(entry) => entry.version,
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
    let discovered = discover_entries(root, previous)?;
    let mut entries = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut symlinks = BTreeMap::new();
    let mut tombstones = previous.tombstones.clone();
    let mut changes = 0_usize;

    for (path, discovered_file) in &discovered.files {
        let old_entry = previous.entries.get(path);
        let unchanged = old_entry.is_some_and(|entry| {
            entry.size == discovered_file.size
                && entry.sha256 == discovered_file.sha256
                && permissions_match(entry.permissions, discovered_file.permissions)
        });
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            // Keep the stored digest/permissions/version, but refresh the recorded
            // mtime to the current on-disk value. Files applied from a remote peer
            // carry the producer's timestamp in the merged manifest, which never
            // equals the local disk mtime; converging it here lets the scan fast
            // path match on the very next cycle instead of re-hashing forever.
            ManifestEntry {
                modified_at_ns: discovered_file.modified_at_ns,
                ..old_entry.clone()
            }
        } else {
            changes = changes.saturating_add(1);
            let version = clock.tick(now_ms, *endpoint_id.as_bytes())?;
            ManifestEntry {
                size: discovered_file.size,
                modified_at_ns: discovered_file.modified_at_ns,
                sha256: discovered_file.sha256.clone(),
                permissions: selected_permissions(
                    old_entry.and_then(|entry| entry.permissions),
                    discovered_file.permissions,
                ),
                version,
            }
        };
        let _ = tombstones.remove(path);
        entries.insert(path.clone(), entry);
    }

    for (path, discovered_directory) in &discovered.directories {
        let old_entry = previous.directories.get(path);
        let unchanged = old_entry.is_some_and(|entry| {
            permissions_match(entry.permissions, discovered_directory.permissions)
        });
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            old_entry.clone()
        } else {
            changes = changes.saturating_add(1);
            DirectoryEntry {
                permissions: selected_permissions(
                    old_entry.and_then(|entry| entry.permissions),
                    discovered_directory.permissions,
                ),
                version: clock.tick(now_ms, *endpoint_id.as_bytes())?,
            }
        };
        let _ = tombstones.remove(path);
        directories.insert(path.clone(), entry);
    }

    for (path, discovered_symlink) in &discovered.symlinks {
        let old_entry = previous.symlinks.get(path);
        let unchanged = old_entry.is_some_and(|entry| entry.target == discovered_symlink.target);
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            old_entry.clone()
        } else {
            changes = changes.saturating_add(1);
            SymlinkEntry {
                target: discovered_symlink.target.clone(),
                version: clock.tick(now_ms, *endpoint_id.as_bytes())?,
            }
        };
        let _ = tombstones.remove(path);
        symlinks.insert(path.clone(), entry);
    }

    for path in previous
        .entries
        .keys()
        .chain(previous.directories.keys())
        .chain(previous.symlinks.keys())
    {
        if !discovered.files.contains_key(path)
            && !discovered.directories.contains_key(path)
            && !discovered.symlinks.contains_key(path)
        {
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
        format_version: MANIFEST_FORMAT_VERSION,
        share_id: previous.share_id,
        scanned_at_ms: now_ms,
        entries,
        directories,
        symlinks,
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
    permissions: Option<u16>,
}

struct DiscoveredDirectory {
    permissions: Option<u16>,
}

struct DiscoveredSymlink {
    target: String,
}

struct DiscoveredEntries {
    files: BTreeMap<String, DiscoveredFile>,
    directories: BTreeMap<String, DiscoveredDirectory>,
    symlinks: BTreeMap<String, DiscoveredSymlink>,
}

fn discover_entries(root: &Path, previous: &Manifest) -> Result<DiscoveredEntries> {
    let metadata = fs::metadata(root)
        .with_context(|| format!("unable to inspect local directory {}", root.display()))?;
    if !metadata.is_dir() {
        bail!("local path {} is not a directory", root.display());
    }

    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut symlinks = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry =
            entry.with_context(|| format!("unable to scan local directory {}", root.display()))?;
        if entry.path() == root {
            continue;
        }
        let file_type = entry.file_type();
        if !file_type.is_dir() && !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }
        if files
            .len()
            .checked_add(directories.len())
            .and_then(|count| count.checked_add(symlinks.len()))
            .is_none_or(|count| count >= MAX_MANIFEST_ENTRIES)
        {
            bail!("local directory exceeds the maximum supported file count");
        }
        let path = relative_manifest_path(root, entry.path())?;
        if file_type.is_symlink() {
            let target = fs::read_link(entry.path())
                .with_context(|| format!("unable to read symlink {}", entry.path().display()))?;
            let target = target
                .to_str()
                .ok_or_else(|| anyhow!("local symlink target is not valid UTF-8"))?
                .to_owned();
            validate_symlink_target(&target)?;
            symlinks.insert(path, DiscoveredSymlink { target });
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("unable to inspect local path {}", entry.path().display()))?;
        if file_type.is_dir() {
            directories.insert(
                path,
                DiscoveredDirectory {
                    permissions: permissions_from_metadata(&metadata),
                },
            );
        } else {
            // Fast path: if the previous manifest holds an entry whose size, mtime and
            // permissions all still match what stat reports, reuse its stored digest
            // instead of re-reading and re-hashing the whole file. Content changes are
            // always reflected in mtime/size (or permissions), so skipping the digest
            // recomputation is safe and turns repeated full-directory scans into
            // stat-only walks.
            let (size, modified_at_ns, sha256, permissions) = match previous.entries.get(&path) {
                Some(old)
                    if old.size == metadata.len()
                        && modified_at_ns(&metadata) == old.modified_at_ns
                        && permissions_match(
                            permissions_from_metadata(&metadata),
                            old.permissions,
                        ) =>
                {
                    (
                        old.size,
                        old.modified_at_ns,
                        old.sha256.clone(),
                        old.permissions,
                    )
                }
                _ => hash_stable_file(entry.path(), &metadata)?,
            };
            files.insert(
                path,
                DiscoveredFile {
                    size,
                    modified_at_ns,
                    sha256,
                    permissions,
                },
            );
        }
    }
    Ok(DiscoveredEntries {
        files,
        directories,
        symlinks,
    })
}

fn hash_stable_file(
    path: &Path,
    expected_metadata: &fs::Metadata,
) -> Result<(u64, u64, String, Option<u16>)> {
    let first_size = expected_metadata.len();
    let first_modified = modified_at_ns(expected_metadata);
    let first_permissions = permissions_from_metadata(expected_metadata);
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
        if after.len() == first_size
            && modified_at_ns(&after) == first_modified
            && permissions_match(first_permissions, permissions_from_metadata(&after))
        {
            return Ok((
                first_size,
                first_modified,
                hex::encode(hasher.finalize()),
                selected_permissions(None, first_permissions),
            ));
        }
    }
    bail!(
        "local file changed while it was being scanned: {}",
        path.display()
    )
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn permissions_from_metadata(metadata: &fs::Metadata) -> Option<u16> {
    use std::os::unix::fs::PermissionsExt as _;

    Some((metadata.permissions().mode() & 0o7777) as u16)
}

#[cfg(not(unix))]
fn permissions_from_metadata(_metadata: &fs::Metadata) -> Option<u16> {
    None
}

#[cfg(unix)]
fn permissions_match(left: Option<u16>, right: Option<u16>) -> bool {
    left == right
}

#[cfg(not(unix))]
fn permissions_match(_left: Option<u16>, _right: Option<u16>) -> bool {
    true
}

#[cfg(unix)]
const fn selected_permissions(_previous: Option<u16>, discovered: Option<u16>) -> Option<u16> {
    discovered
}

#[cfg(not(unix))]
fn selected_permissions(previous: Option<u16>, _discovered: Option<u16>) -> Option<u16> {
    previous
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
            Some(ManifestRecordRef::Directory(entry)) => {
                merged.directories.insert(path.clone(), entry.clone());
            }
            Some(ManifestRecordRef::Symlink(entry)) => {
                merged.symlinks.insert(path.clone(), entry.clone());
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

fn validate_manifest_hierarchy(manifest: &Manifest) -> Result<()> {
    for path in manifest
        .entries
        .keys()
        .chain(manifest.directories.keys())
        .chain(manifest.symlinks.keys())
    {
        let mut ancestor = String::new();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            if manifest.entries.contains_key(&ancestor) || manifest.symlinks.contains_key(&ancestor)
            {
                bail!("manifest live path has a descendant: {ancestor}");
            }
            if manifest.tombstones.contains_key(&ancestor) {
                bail!("manifest has a live path below a tombstone: {ancestor}");
            }
        }
    }
    Ok(())
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

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

    #[cfg(unix)]
    #[test]
    fn scanner_tracks_symlink_targets_without_following_them() {
        let temporary = TempDir::new().unwrap();
        fs::write(temporary.path().join("target.txt"), "target").unwrap();
        std::os::unix::fs::symlink("target.txt", temporary.path().join("alias.txt")).unwrap();
        let share_id = ShareId([8; 32]);
        let endpoint = SecretKey::from_bytes(&[9; 32]).public();
        let scanned = scan_manifest(
            temporary.path(),
            &Manifest::empty(share_id, 1),
            ClockState::new(),
            &endpoint,
            2,
        )
        .unwrap();
        assert_eq!(scanned.manifest.symlinks["alias.txt"].target, "target.txt");
        assert!(!scanned.manifest.entries.contains_key("alias.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn scanner_tracks_file_and_directory_permissions() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path().join("private");
        let empty_directory = temporary.path().join("empty");
        let file = directory.join("config.txt");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&empty_directory).unwrap();
        fs::write(&file, "one").unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&empty_directory, fs::Permissions::from_mode(0o710)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let share_id = ShareId([4; 32]);
        let endpoint = SecretKey::from_bytes(&[5; 32]).public();
        let first = scan_manifest(
            temporary.path(),
            &Manifest::empty(share_id, 1),
            ClockState::new(),
            &endpoint,
            2,
        )
        .unwrap();
        assert_eq!(
            first.manifest.entries["private/config.txt"].permissions,
            Some(0o640)
        );
        assert_eq!(
            first.manifest.directories["private"].permissions,
            Some(0o750)
        );
        assert_eq!(first.manifest.directories["empty"].permissions, Some(0o710));

        let unchanged = scan_manifest(
            temporary.path(),
            &first.manifest,
            first.clock.clone(),
            &endpoint,
            3,
        )
        .unwrap();
        assert_eq!(
            unchanged.manifest.entries["private/config.txt"].version,
            first.manifest.entries["private/config.txt"].version
        );
        assert_eq!(
            unchanged.manifest.directories["private"].version,
            first.manifest.directories["private"].version
        );

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let changed = scan_manifest(
            temporary.path(),
            &unchanged.manifest,
            unchanged.clock,
            &endpoint,
            4,
        )
        .unwrap();
        assert_eq!(
            changed.manifest.entries["private/config.txt"].permissions,
            Some(0o600)
        );
        assert_eq!(
            changed.manifest.directories["private"].permissions,
            Some(0o700)
        );
        assert_ne!(
            changed.manifest.entries["private/config.txt"].version,
            unchanged.manifest.entries["private/config.txt"].version
        );
        assert_ne!(
            changed.manifest.directories["private"].version,
            unchanged.manifest.directories["private"].version
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_manifests_gain_permissions_on_the_next_scan() {
        let temporary = TempDir::new().unwrap();
        let file = temporary.path().join("config.txt");
        fs::write(&file, "one").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let share_id = ShareId([6; 32]);
        let endpoint = SecretKey::from_bytes(&[7; 32]).public();
        let scanned = scan_manifest(
            temporary.path(),
            &Manifest::empty(share_id, 1),
            ClockState::new(),
            &endpoint,
            2,
        )
        .unwrap();
        let mut legacy = serde_json::to_value(&scanned.manifest).unwrap();
        legacy["format_version"] = serde_json::json!(LEGACY_MANIFEST_FORMAT_VERSION);
        legacy["directories"] = serde_json::json!({});
        legacy["entries"]["config.txt"]
            .as_object_mut()
            .unwrap()
            .remove("permissions");
        let legacy: Manifest = serde_json::from_value(legacy).unwrap();
        legacy.validate(share_id).unwrap();

        let migrated =
            scan_manifest(temporary.path(), &legacy, scanned.clock, &endpoint, 3).unwrap();
        assert_eq!(migrated.manifest.format_version, MANIFEST_FORMAT_VERSION);
        assert_eq!(
            migrated.manifest.entries["config.txt"].permissions,
            Some(0o640)
        );
        assert_ne!(
            migrated.manifest.entries["config.txt"].version,
            legacy.entries["config.txt"].version
        );
    }
}
