use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::Path,
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::EndpointId;
use sha2::{Digest as _, Sha256};
use walkdir::WalkDir;

use crate::types::ClockState;

use super::{
    LEGACY_MANIFEST_FORMAT_VERSION, MANIFEST_FORMAT_VERSION, MAX_MANIFEST_ENTRIES,
    model::{
        DirectoryEntry, Manifest, ManifestEntry, SymlinkEntry, Tombstone, validate_symlink_target,
    },
    path::relative_manifest_path,
};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

pub struct ScanResult<M = Manifest> {
    pub manifest: M,
    pub clock: ClockState,
    pub files: usize,
    pub tombstones: usize,
    pub changes: usize,
    pub changed: bool,
    pub manifest_changed: bool,
}

/// Scans a root directory and creates a manifest. State is returned rather than persisted so the
/// caller can persist the HLC before the manifest.
pub fn scan_manifest(
    root: &Path,
    previous: &Manifest,
    clock: ClockState,
    endpoint_id: &EndpointId,
    now_ms: u64,
) -> Result<ScanResult> {
    previous.validate(previous.share_id)?;
    let scanned =
        scan_manifest_cached_after_validation(root, previous, clock, endpoint_id, now_ms)?;
    let mut manifest = scanned.manifest.into_owned();
    manifest.scanned_at_ms = now_ms;
    Ok(ScanResult {
        manifest,
        clock: scanned.clock,
        files: scanned.files,
        tombstones: scanned.tombstones,
        changes: scanned.changes,
        changed: scanned.changed,
        manifest_changed: scanned.manifest_changed,
    })
}

pub fn scan_manifest_cached_after_validation<'a>(
    root: &Path,
    previous: &'a Manifest,
    mut clock: ClockState,
    endpoint_id: &EndpointId,
    now_ms: u64,
) -> Result<ScanResult<Cow<'a, Manifest>>> {
    clock.validate()?;
    // Windows manifests have no POSIX permissions; only legacy manifests should synthesize them.
    let unknown_permissions_match = previous.format_version != LEGACY_MANIFEST_FORMAT_VERSION;
    let discovered = discover_entries(root, previous, unknown_permissions_match)?;
    if discovered.matches_previous(previous, unknown_permissions_match) {
        return Ok(ScanResult {
            manifest: Cow::Borrowed(previous),
            clock,
            files: previous.entries.len(),
            tombstones: previous.tombstones.len(),
            changes: 0,
            changed: false,
            manifest_changed: false,
        });
    }
    let mut entries = BTreeMap::new();
    let mut directories = BTreeMap::new();
    // Windows follows Syncthing's policy: remote symlinks remain as unsupported index state
    // without being materialized in the shared directory.
    #[cfg(windows)]
    let mut symlinks = previous.symlinks.clone();
    #[cfg(not(windows))]
    let mut symlinks = BTreeMap::new();
    let mut tombstones = previous.tombstones.clone();
    let mut changes = 0_usize;

    for (path, discovered_file) in discovered.files {
        let old_entry = previous.entries.get(&path);
        let unchanged = old_entry.is_some_and(|entry| {
            entry.size == discovered_file.size
                && entry.sha256 == discovered_file.sha256
                && permissions_match(
                    entry.permissions,
                    discovered_file.permissions,
                    unknown_permissions_match,
                )
        });
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            // Keep the stored digest/permissions/version, but refresh the recorded
            // mtime to the current on-disk value. Files applied from a remote peer
            // carry the producer's timestamp in the merged manifest, which never
            // equals the local disk mtime; converging it here lets the scan fast
            // path match on the very next cycle instead of re-hashing forever.
            ManifestEntry {
                size: old_entry.size,
                modified_at_ns: discovered_file.modified_at_ns,
                sha256: discovered_file.sha256.into_owned(),
                permissions: old_entry.permissions,
                version: old_entry.version,
            }
        } else {
            changes = changes.saturating_add(1);
            let version = clock.tick(now_ms, *endpoint_id.as_bytes())?;
            ManifestEntry {
                size: discovered_file.size,
                modified_at_ns: discovered_file.modified_at_ns,
                sha256: discovered_file.sha256.into_owned(),
                permissions: selected_permissions(
                    old_entry.and_then(|entry| entry.permissions),
                    discovered_file.permissions,
                ),
                version,
            }
        };
        let _ = tombstones.remove(&path);
        let _ = symlinks.remove(&path);
        entries.insert(path, entry);
    }

    for (path, discovered_directory) in discovered.directories {
        let old_entry = previous.directories.get(&path);
        let unchanged = old_entry.is_some_and(|entry| {
            permissions_match(
                entry.permissions,
                discovered_directory.permissions,
                unknown_permissions_match,
            )
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
        let _ = tombstones.remove(&path);
        let _ = symlinks.remove(&path);
        directories.insert(path, entry);
    }

    for (path, discovered_symlink) in discovered.symlinks {
        let old_entry = previous.symlinks.get(&path);
        let unchanged = old_entry.is_some_and(|entry| entry.target == discovered_symlink.target);
        let entry = if let Some(old_entry) = old_entry.filter(|_| unchanged) {
            old_entry.clone()
        } else {
            changes = changes.saturating_add(1);
            SymlinkEntry {
                target: discovered_symlink.target,
                version: clock.tick(now_ms, *endpoint_id.as_bytes())?,
            }
        };
        let _ = tombstones.remove(&path);
        symlinks.insert(path, entry);
    }

    for path in previous
        .entries
        .keys()
        .chain(previous.directories.keys())
        .chain(previous.symlinks.keys())
    {
        #[cfg(windows)]
        if previous.symlinks.contains_key(path) {
            continue;
        }
        if !entries.contains_key(path)
            && !directories.contains_key(path)
            && !symlinks.contains_key(path)
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

    let manifest_changed = previous.format_version != MANIFEST_FORMAT_VERSION
        || previous.entries != entries
        || previous.directories != directories
        || previous.symlinks != symlinks
        || previous.tombstones != tombstones;
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
        manifest: Cow::Owned(manifest),
        clock,
        changes,
        changed: changes > 0,
        manifest_changed,
    })
}

#[derive(Clone)]
struct DiscoveredFile<'a> {
    size: u64,
    modified_at_ns: u64,
    sha256: Cow<'a, str>,
    permissions: Option<u16>,
}

struct DiscoveredDirectory {
    permissions: Option<u16>,
}

struct DiscoveredSymlink {
    target: String,
}

struct DiscoveredEntries<'a> {
    files: BTreeMap<String, DiscoveredFile<'a>>,
    directories: BTreeMap<String, DiscoveredDirectory>,
    symlinks: BTreeMap<String, DiscoveredSymlink>,
}

impl DiscoveredEntries<'_> {
    fn matches_previous(&self, previous: &Manifest, unknown_permissions_match: bool) -> bool {
        if previous.format_version != MANIFEST_FORMAT_VERSION
            || previous.entries.len() != self.files.len()
            || previous.directories.len() != self.directories.len()
            || !previous
                .entries
                .iter()
                .zip(&self.files)
                .all(|((old_path, old), (path, file))| {
                    old_path == path
                        && old.size == file.size
                        && old.modified_at_ns == file.modified_at_ns
                        && old.sha256 == file.sha256
                        && permissions_match(
                            old.permissions,
                            file.permissions,
                            unknown_permissions_match,
                        )
                })
            || !previous.directories.iter().zip(&self.directories).all(
                |((old_path, old), (path, directory))| {
                    old_path == path
                        && permissions_match(
                            old.permissions,
                            directory.permissions,
                            unknown_permissions_match,
                        )
                },
            )
        {
            return false;
        }
        #[cfg(windows)]
        {
            self.symlinks.is_empty()
        }
        #[cfg(not(windows))]
        {
            previous.symlinks.len() == self.symlinks.len()
                && previous.symlinks.iter().zip(&self.symlinks).all(
                    |((old_path, old), (path, link))| old_path == path && old.target == link.target,
                )
        }
    }
}

fn discover_entries<'a>(
    root: &Path,
    previous: &'a Manifest,
    unknown_permissions_match: bool,
) -> Result<DiscoveredEntries<'a>> {
    let metadata = fs::metadata(root)
        .with_context(|| format!("unable to inspect local directory {}", root.display()))?;
    if !metadata.is_dir() {
        bail!("local path {} is not a directory", root.display());
    }

    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();
    #[cfg(windows)]
    let symlinks = BTreeMap::new();
    #[cfg(not(windows))]
    let mut symlinks = BTreeMap::new();
    let mut hash_buffer = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
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
            // Match Syncthing: Windows does not publish local symlinks. Remote symlinks are
            // retained separately by scan_manifest as unsupported synchronized state.
            #[cfg(windows)]
            {
                continue;
            }
            #[cfg(not(windows))]
            {
                let target = fs::read_link(entry.path()).with_context(|| {
                    format!("unable to read symlink {}", entry.path().display())
                })?;
                let target = target
                    .to_str()
                    .ok_or_else(|| anyhow!("local symlink target is not valid UTF-8"))?
                    .to_owned();
                validate_symlink_target(&target)?;
                symlinks.insert(path, DiscoveredSymlink { target });
                continue;
            }
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
                            unknown_permissions_match,
                        ) =>
                {
                    (
                        old.size,
                        old.modified_at_ns,
                        Cow::Borrowed(old.sha256.as_str()),
                        old.permissions,
                    )
                }
                _ => {
                    if hash_buffer.is_empty() {
                        hash_buffer.resize(HASH_BUFFER_SIZE, 0);
                    }
                    let (size, modified_at_ns, sha256, permissions) =
                        hash_stable_file(entry.path(), &metadata, &mut hash_buffer)?;
                    (size, modified_at_ns, Cow::Owned(sha256), permissions)
                }
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
    buffer: &mut [u8],
) -> Result<(u64, u64, String, Option<u16>)> {
    let first_size = expected_metadata.len();
    let first_modified = modified_at_ns(expected_metadata);
    let first_permissions = permissions_from_metadata(expected_metadata);
    for _ in 0..3 {
        let mut file = File::open(path)
            .with_context(|| format!("unable to open local file {}", path.display()))?;
        let mut hasher = Sha256::new();
        loop {
            let count = file
                .read(buffer)
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
            && permissions_match(first_permissions, permissions_from_metadata(&after), false)
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
const fn permissions_from_metadata(_metadata: &fs::Metadata) -> Option<u16> {
    None
}

#[cfg(unix)]
fn permissions_match(left: Option<u16>, right: Option<u16>, unknown_matches: bool) -> bool {
    (unknown_matches && (left.is_none() || right.is_none())) || left == right
}

#[cfg(not(unix))]
const fn permissions_match(
    _left: Option<u16>,
    _right: Option<u16>,
    _unknown_matches: bool,
) -> bool {
    true
}

#[cfg(unix)]
const fn selected_permissions(_previous: Option<u16>, discovered: Option<u16>) -> Option<u16> {
    discovered
}

#[cfg(not(unix))]
const fn selected_permissions(previous: Option<u16>, _discovered: Option<u16>) -> Option<u16> {
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
