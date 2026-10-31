//! Manifest model, scanning, path validation, and merge rules.
//!
//! - `model`: serialized manifest records, their validation, and the sync digest.
//! - `scan`: filesystem discovery and combining a scan with the previous manifest.
//! - `path`: manifest-relative path validation and mapping.
//! - `merge`: last-writer-wins selection used to reconcile peer manifests.

pub use merge::{merge_manifests, select_record};
pub use model::{
    DirectoryEntry, Manifest, ManifestEntry, ManifestRecord, ManifestRecordRef, SymlinkEntry,
    Tombstone,
};
pub use path::{current_time_ms, path_for_manifest, validate_manifest_path};
pub use scan::{ScanResult, scan_manifest};

pub const MAX_MANIFEST_ENTRIES: usize = 100_000;
pub const MANIFEST_FORMAT_VERSION: u16 = 3;

pub(crate) const PREVIOUS_MANIFEST_FORMAT_VERSION: u16 = 2;
pub(crate) const LEGACY_MANIFEST_FORMAT_VERSION: u16 = 1;

mod merge;
mod model;
mod path;
mod scan;

pub(crate) use scan::scan_manifest_cached_after_validation;

#[cfg(test)]
pub(crate) use model::{MAX_CACHED_AUTHORS, VALID_AUTHORS, validate_timestamp};

#[cfg(test)]
mod tests;
