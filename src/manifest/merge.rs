use std::collections::BTreeSet;

use anyhow::{Result, bail};

use super::model::{Manifest, ManifestRecordRef};

pub fn merge_manifests(local: &Manifest, remote: &Manifest, now_ms: u64) -> Result<Manifest> {
    local.validate(local.share_id)?;
    remote.validate(local.share_id)?;
    let mut merged = Manifest::empty(local.share_id, now_ms);
    let paths = local.paths().chain(remote.paths()).collect::<BTreeSet<_>>();
    for path in paths {
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

pub fn validate_manifest_hierarchy(manifest: &Manifest) -> Result<()> {
    for path in manifest
        .entries
        .keys()
        .chain(manifest.directories.keys())
        .chain(manifest.symlinks.keys())
    {
        for (separator, _) in path.match_indices('/') {
            let ancestor = &path[..separator];
            if manifest.entries.contains_key(ancestor) || manifest.symlinks.contains_key(ancestor) {
                bail!("manifest live path has a descendant: {ancestor}");
            }
            if manifest.tombstones.contains_key(ancestor) {
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
