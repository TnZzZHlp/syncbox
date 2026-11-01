use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use anyhow::{Result, anyhow, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::types::{HlcTimestamp, ShareId};

use super::merge::validate_manifest_hierarchy;
use super::{
    LEGACY_MANIFEST_FORMAT_VERSION, MANIFEST_FORMAT_VERSION, MAX_MANIFEST_ENTRIES,
    PREVIOUS_MANIFEST_FORMAT_VERSION, path::validate_manifest_path,
};

/// Cache of HLC authors already validated as compressed endpoint IDs.
pub const MAX_CACHED_AUTHORS: usize = 256;

thread_local! {
    pub(crate) static VALID_AUTHORS: RefCell<Vec<[u8; 32]>> = const { RefCell::new(Vec::new()) };
}

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

    pub(crate) fn paths(&self) -> impl Iterator<Item = &String> {
        self.entries
            .keys()
            .chain(self.directories.keys())
            .chain(self.symlinks.keys())
            .chain(self.tombstones.keys())
    }

    pub fn all_paths(&self) -> BTreeSet<String> {
        self.paths().cloned().collect()
    }

    /// Hashes only synchronized state. Scan timestamps and local filesystem mtimes are excluded
    /// because peers can legitimately record different values for the same synchronized content.
    pub fn sync_digest(&self, expected_share_id: ShareId) -> Result<[u8; 32]> {
        self.validate(expected_share_id)?;
        Ok(self.sync_digest_after_validation())
    }

    /// Computes the digest without validation. The caller must validate the manifest first.
    pub(crate) fn sync_digest_after_validation(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"syncbox-manifest-digest-v1\0");
        hasher.update(&self.format_version.to_be_bytes());
        hasher.update(self.share_id.as_bytes());

        update_digest_len(&mut hasher, self.entries.len());
        for (path, entry) in &self.entries {
            update_digest_bytes(&mut hasher, path.as_bytes());
            hasher.update(&entry.size.to_be_bytes());
            update_digest_bytes(&mut hasher, entry.sha256.as_bytes());
            update_digest_permissions(&mut hasher, entry.permissions);
            update_digest_timestamp(&mut hasher, entry.version);
        }

        update_digest_len(&mut hasher, self.directories.len());
        for (path, entry) in &self.directories {
            update_digest_bytes(&mut hasher, path.as_bytes());
            update_digest_permissions(&mut hasher, entry.permissions);
            update_digest_timestamp(&mut hasher, entry.version);
        }

        update_digest_len(&mut hasher, self.symlinks.len());
        for (path, entry) in &self.symlinks {
            update_digest_bytes(&mut hasher, path.as_bytes());
            update_digest_bytes(&mut hasher, entry.target.as_bytes());
            update_digest_timestamp(&mut hasher, entry.version);
        }

        update_digest_len(&mut hasher, self.tombstones.len());
        for (path, tombstone) in &self.tombstones {
            update_digest_bytes(&mut hasher, path.as_bytes());
            update_digest_timestamp(&mut hasher, tombstone.version);
        }

        *hasher.finalize().as_bytes()
    }
}

fn update_digest_len(hasher: &mut blake3::Hasher, length: usize) {
    hasher.update(
        &u64::try_from(length)
            .expect("manifest lengths fit in u64")
            .to_be_bytes(),
    );
}

fn update_digest_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    update_digest_len(hasher, value.len());
    hasher.update(value);
}

fn update_digest_permissions(hasher: &mut blake3::Hasher, permissions: Option<u16>) {
    match permissions {
        Some(permissions) => {
            hasher.update(&[1]);
            hasher.update(&permissions.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn update_digest_timestamp(hasher: &mut blake3::Hasher, timestamp: HlcTimestamp) {
    let mut bytes = [0_u8; 44];
    bytes[..8].copy_from_slice(&timestamp.wall_ms.to_be_bytes());
    bytes[8..12].copy_from_slice(&timestamp.counter.to_be_bytes());
    bytes[12..].copy_from_slice(&timestamp.author);
    hasher.update(&bytes);
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
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub fn validate_symlink_target(target: &str) -> Result<()> {
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

pub fn validate_timestamp(timestamp: &HlcTimestamp) -> Result<()> {
    if VALID_AUTHORS.with(|authors| authors.borrow().contains(&timestamp.author)) {
        return Ok(());
    }
    EndpointId::from_bytes(&timestamp.author)
        .map_err(|_| anyhow!("manifest has an invalid HLC author"))?;
    VALID_AUTHORS.with(|authors| {
        let mut authors = authors.borrow_mut();
        if authors.len() < MAX_CACHED_AUTHORS {
            authors.push(timestamp.author);
        }
    });
    Ok(())
}

pub fn validate_permissions(permissions: Option<u16>) -> Result<()> {
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
