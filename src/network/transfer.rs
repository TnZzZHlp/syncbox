use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::debug;

use crate::{
    chunk::{MAX_CHUNK_BYTES, read_chunk, write_chunk},
    manifest::{Manifest, ManifestRecordRef, current_time_ms, select_record},
    types::{PROTOCOL_VERSION, ShareId},
};

use super::{
    HASH_BUFFER_BYTES,
    io::{RecvStream, SendStream},
    local::{
        config_root, ensure_local_directory, local_file_matches_entry, manifest_path_depth,
        remove_local_path, safe_local_path, set_local_directory_permissions,
        set_local_file_permissions, write_local_file, write_local_staged_file, write_local_symlink,
    },
    run_blocking,
    state::{ActiveShare, unsupported_symlink_count},
    wire::{
        FilePayload, MAX_TRANSFER_FILES, TransferFile, TransferReady, TransferRequest,
        validate_file_payloads, validate_path_list, validate_transfer_file_shapes,
        validate_transfer_files, validate_transfer_files_iter, validate_transfer_ready,
    },
};

const MIN_BINARY_SEARCH_RESUMES: usize = 64;

/// Result of applying a peer's manifest and staged files.
pub struct ApplyOutcome {
    pub(crate) pending_downloads: usize,
    pub(crate) applied_records: usize,
    pub(crate) unsupported_items: usize,
}
pub fn make_transfer_request(
    share: &Arc<ActiveShare>,
    local: &Manifest,
    remote: &Manifest,
) -> Result<(TransferRequest, usize)> {
    let mut download_paths = Vec::new();
    let mut download_resumes = Vec::new();
    for (path, remote_entry) in &remote.entries {
        let remote_record = ManifestRecordRef::File(remote_entry);
        if matches!(select_record(local.record(path), Some(remote_record)), Some(selected) if selected.version() == remote_record.version() && selected.is_tombstone() == remote_record.is_tombstone())
        {
            let local_content_matches = local.entries.get(path).is_some_and(|entry| {
                entry.size == remote_entry.size && entry.sha256 == remote_entry.sha256
            });
            if !local_content_matches {
                download_paths.push(path.clone());
                download_resumes.push(TransferFile {
                    path: path.clone(),
                    sha256: remote_entry.sha256.clone(),
                    size: remote_entry.size,
                    offset: partial_size(share, path, &remote_entry.sha256, remote_entry.size)?,
                });
                if download_paths.len() == MAX_TRANSFER_FILES {
                    break;
                }
            }
        }
    }
    let mut uploads = Vec::new();
    let mut requested_uploads = 0_usize;
    for (path, local_entry) in &local.entries {
        let local_record = ManifestRecordRef::File(local_entry);
        let selected = select_record(Some(local_record), remote.record(path));
        let local_wins = matches!(selected, Some(winner) if winner.version() == local_record.version() && !winner.is_tombstone());
        let remote_content_matches = remote.entries.get(path).is_some_and(|entry| {
            entry.size == local_entry.size && entry.sha256 == local_entry.sha256
        });
        if local_wins && !remote_content_matches {
            requested_uploads += 1;
            if uploads.len() < MAX_TRANSFER_FILES {
                uploads.push(TransferFile {
                    path: path.clone(),
                    sha256: local_entry.sha256.clone(),
                    size: local_entry.size,
                    offset: 0,
                });
            }
        }
    }
    let pending_updates = requested_uploads.saturating_sub(uploads.len());
    Ok((
        TransferRequest {
            protocol_version: PROTOCOL_VERSION,
            share_id: share.share_id,
            download_paths,
            download_resumes,
            uploads,
        },
        pending_updates,
    ))
}

#[allow(dead_code)]
pub fn build_file_payloads(
    share: &Arc<ActiveShare>,
    manifest: &Manifest,
    paths: &[String],
) -> Result<Vec<FilePayload>> {
    validate_path_list(paths)?;
    let root = config_root(&share.config()?)?;
    let mut files = Vec::new();
    for path in paths {
        let Some(entry) = manifest.entries.get(path) else {
            continue;
        };
        let target = safe_local_path(&root, path, false)?;
        // Do not follow a leaf symlink. A stale manifest entry may otherwise cause a file outside
        // the shared directory to be uploaded after a local path was replaced with a symlink.
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            _ => continue,
        };
        if metadata.len() != entry.size {
            continue;
        }
        let bytes = fs::read(&target)
            .with_context(|| format!("unable to read shared file {}", target.display()))?;
        let after_read = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            _ => continue,
        };
        if after_read.len() != entry.size || bytes.len() as u64 != entry.size {
            continue;
        }
        if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            continue;
        }
        files.push(FilePayload {
            path: path.clone(),
            sha256: entry.sha256.clone(),
            content: URL_SAFE_NO_PAD.encode(bytes),
        });
    }
    Ok(files)
}

#[cfg(test)]
pub fn chunk_ranges(total: u64, offset: u64, chunk_size: usize) -> Vec<(u64, usize)> {
    let mut ranges = Vec::new();
    let mut current = offset.min(total);
    while current < total {
        let length = usize::try_from((total - current).min(chunk_size as u64))
            .expect("chunk length is bounded by the requested chunk size");
        ranges.push((current, length));
        current += length as u64;
    }
    ranges.push((current, 0));
    ranges
}

pub fn partial_path(share: &Arc<ActiveShare>, manifest_path: &str, sha256: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(manifest_path.as_bytes());
    hasher.update([0]);
    hasher.update(sha256.as_bytes());
    let mut name = *b"chunk-0000000000000000000000000000000000000000000000000000000000000000.part";
    hex::encode_to_slice(hasher.finalize(), &mut name[6..70])
        .expect("SHA-256 encodes to 64 hexadecimal bytes");
    share
        .paths
        .share_tmp_dir(share.share_id)
        .join(std::str::from_utf8(&name).expect("partial file name contains only ASCII characters"))
}

pub fn partial_size(
    share: &Arc<ActiveShare>,
    manifest_path: &str,
    sha256: &str,
    size: u64,
) -> Result<u64> {
    let path = partial_path(share, manifest_path, sha256);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= size => Ok(metadata.len()),
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(&path).with_context(|| {
                format!(
                    "unable to remove oversized transfer partial {}",
                    path.display()
                )
            })?;
            Ok(0)
        }
        Ok(_) => bail!("transfer partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error)
            .with_context(|| format!("unable to inspect transfer partial {}", path.display())),
    }
}

pub fn make_transfer_ready(
    share: &Arc<ActiveShare>,
    request: &TransferRequest,
    manifest: &Manifest,
) -> Result<TransferReady> {
    validate_transfer_files(&request.uploads, manifest)?;
    let uploads = request
        .uploads
        .iter()
        .map(|file| {
            Ok(TransferFile {
                path: file.path.clone(),
                sha256: file.sha256.clone(),
                size: file.size,
                offset: partial_size(share, &file.path, &file.sha256, file.size)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(TransferReady {
        protocol_version: PROTOCOL_VERSION,
        share_id: request.share_id,
        uploads,
    })
}

pub fn build_transfer_files(
    manifest: &Manifest,
    paths: &[String],
    resumes: &[TransferFile],
) -> Result<Vec<TransferFile>> {
    validate_path_list(paths)?;
    validate_transfer_file_shapes(resumes)?;
    let use_binary_search = paths.len() >= MIN_BINARY_SEARCH_RESUMES
        && resumes.len() >= MIN_BINARY_SEARCH_RESUMES
        && resumes.is_sorted_by(|left, right| left.path <= right.path);
    let mut files = Vec::new();
    for path in paths {
        let Some(entry) = manifest.entries.get(path) else {
            continue;
        };
        let resume = if use_binary_search {
            resumes
                .binary_search_by(|resume| resume.path.cmp(path))
                .ok()
                .map(|index| &resumes[index])
        } else {
            resumes.iter().find(|resume| resume.path == *path)
        };
        let offset = resume
            .filter(|resume| resume.sha256 == entry.sha256 && resume.size == entry.size)
            .map_or(0, |resume| resume.offset.min(entry.size));
        files.push(TransferFile {
            path: path.clone(),
            sha256: entry.sha256.clone(),
            size: entry.size,
            offset,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    Ok(files)
}

pub async fn send_upload_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    requested: &[TransferFile],
    ready: &[TransferFile],
    send: &mut SendStream,
) -> Result<()> {
    validate_transfer_file_shapes(requested)?;
    validate_transfer_file_shapes(ready)?;
    if requested.len() != ready.len() {
        bail!("upload resume list has an unexpected length");
    }
    for (request, resume) in requested.iter().zip(ready) {
        if request.path != resume.path
            || request.sha256 != resume.sha256
            || request.size != resume.size
        {
            bail!("upload resume metadata does not match the request");
        }
    }
    send_file_chunks_from_root(share, peer_endpoint_id, ready, send).await
}

pub async fn send_file_chunks_from_root<W: tokio::io::AsyncWrite + Unpin>(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    send: &mut W,
) -> Result<()> {
    let root = config_root(&share.config()?)?;
    let mut buffer = Vec::new();
    for (file_index, file) in files.iter().enumerate() {
        let file_index = u32::try_from(file_index).context("transfer file index overflow")?;
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "starting file upload"
        );
        let target = safe_local_path(&root, &file.path, false)?;
        let metadata = fs::symlink_metadata(&target)
            .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != file.size {
            bail!(
                "shared file changed before chunk transfer: {}",
                target.display()
            );
        }
        let mut source = tokio::fs::File::open(&target)
            .await
            .with_context(|| format!("unable to open shared file {}", target.display()))?;
        if file.offset != 0 {
            source
                .seek(std::io::SeekFrom::Start(file.offset))
                .await
                .with_context(|| format!("unable to seek shared file {}", target.display()))?;
        }
        let required = usize::try_from(
            file.size
                .saturating_sub(file.offset)
                .min(MAX_CHUNK_BYTES as u64),
        )
        .context("transfer chunk size does not fit this platform")?;
        if buffer.len() < required {
            if buffer.is_empty() {
                buffer = vec![0_u8; required];
            } else {
                buffer.resize(required, 0);
            }
        }
        let mut offset = file.offset;
        while offset < file.size {
            let wanted = usize::try_from((file.size - offset).min(buffer.len() as u64))
                .context("transfer chunk size does not fit this platform")?;
            let count = source
                .read(&mut buffer[..wanted])
                .await
                .with_context(|| format!("unable to read shared file {}", target.display()))?;
            if count == 0 {
                bail!(
                    "shared file ended during chunk transfer: {}",
                    target.display()
                );
            }
            write_chunk(send, file_index, offset, &buffer[..count]).await?;
            offset += count as u64;
        }
        let after = fs::symlink_metadata(&target)
            .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
        if !after.is_file() || after.len() != file.size {
            bail!(
                "shared file changed during chunk transfer: {}",
                target.display()
            );
        }
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "completed file upload"
        );
    }
    Ok(())
}

pub fn ensure_partial_file(path: &Path, offset: u64) -> Result<fs::File> {
    let previous_length = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(metadata.len()),
        Ok(_) => bail!("transfer partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("unable to inspect transfer partial {}", path.display()));
        }
    };
    let open = || {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(previous_length.is_none())
            .open(path)
    };
    let file = match open() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && previous_length.is_none() => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("unable to create transfer state {}", parent.display())
                })?;
            }
            open()
        }
        result => result,
    }
    .with_context(|| format!("unable to open transfer partial {}", path.display()))?;
    if previous_length.unwrap_or(0) != offset {
        file.set_len(offset)
            .with_context(|| format!("unable to resize transfer partial {}", path.display()))?;
    }
    Ok(file)
}

pub fn verify_partial(path: &Path, file: &TransferFile, buffer: &mut Vec<u8>) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect transfer partial {}", path.display()))?;
    if !metadata.is_file() || metadata.len() != file.size {
        bail!("transfer partial has an invalid size");
    }
    let mut source = fs::File::open(path)
        .with_context(|| format!("unable to open transfer partial {}", path.display()))?;
    let mut hasher = Sha256::new();
    if buffer.len() < HASH_BUFFER_BYTES {
        buffer.resize(HASH_BUFFER_BYTES, 0);
    }
    loop {
        let count = source
            .read(&mut buffer[..HASH_BUFFER_BYTES])
            .with_context(|| format!("unable to read transfer partial {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if hex::encode(hasher.finalize()) != file.sha256 {
        fs::remove_file(path).with_context(|| {
            format!(
                "transfer partial hash does not match its manifest for {}; unable to remove invalid transfer partial",
                file.path
            )
        })?;
        bail!(
            "transfer partial hash does not match its manifest for {}",
            file.path
        );
    }
    Ok(())
}

pub async fn receive_file_chunks<R: tokio::io::AsyncRead + Unpin>(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    recv: &mut R,
) -> Result<Vec<CompletedFile>> {
    validate_transfer_file_shapes(files)?;
    let mut completed = Vec::new();
    let mut data = Vec::new();
    for (file_index, file) in files.iter().enumerate() {
        let file_index = u32::try_from(file_index).context("transfer file index overflow")?;
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "starting file receive"
        );
        let partial = partial_path(share, &file.path, &file.sha256);
        let destination = ensure_partial_file(&partial, file.offset)
            .with_context(|| format!("unable to prepare transfer for {}", file.path))?;
        let mut destination = tokio::fs::File::from_std(destination);
        if file.offset != 0 {
            destination
                .seek(std::io::SeekFrom::Start(file.offset))
                .await
                .with_context(|| {
                    format!("unable to seek transfer partial {}", partial.display())
                })?;
        }
        let mut offset = file.offset;
        while offset < file.size {
            let count = read_chunk(recv, file_index, offset, file.size - offset, &mut data).await?;
            destination
                .write_all(&data[..count])
                .await
                .with_context(|| {
                    format!("unable to write transfer partial {}", partial.display())
                })?;
            offset += count as u64;
        }
        destination
            .sync_all()
            .await
            .with_context(|| format!("unable to flush transfer partial {}", partial.display()))?;
        drop(destination);
        run_blocking(|| verify_partial(&partial, file, &mut data))?;
        completed.push(CompletedFile {
            file: file.clone(),
            staged_path: partial,
        });
        debug!(
            share_id = %share.share_id,
            peer_endpoint_id = %peer_endpoint_id,
            path = %file.path,
            size = file.size,
            offset = file.offset,
            "completed file receive"
        );
    }
    Ok(completed)
}

pub async fn receive_download_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    files: &[TransferFile],
    recv: &mut RecvStream,
) -> Result<Vec<CompletedFile>> {
    receive_file_chunks(share, peer_endpoint_id, files, recv).await
}

pub async fn receive_upload_chunks(
    share: &Arc<ActiveShare>,
    peer_endpoint_id: EndpointId,
    share_id: ShareId,
    requested: &[TransferFile],
    ready: &[TransferFile],
    recv: &mut RecvStream,
) -> Result<Vec<CompletedFile>> {
    validate_transfer_ready(
        &TransferReady {
            protocol_version: PROTOCOL_VERSION,
            share_id,
            uploads: ready,
        },
        share_id,
        requested,
    )?;
    receive_file_chunks(share, peer_endpoint_id, ready, recv).await
}

#[allow(dead_code)]
pub enum IncomingFile<'a> {
    Bytes(Vec<u8>),
    Staged(&'a Path),
}

pub struct CompletedFile {
    pub(crate) file: TransferFile,
    pub(crate) staged_path: PathBuf,
}

#[allow(dead_code)]
pub fn apply_remote_transfer(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    files: &[FilePayload],
) -> Result<ApplyOutcome> {
    remote.validate(share.share_id)?;
    validate_file_payloads(files, remote)?;
    let mut file_data = BTreeMap::new();
    for file in files {
        let bytes = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        file_data.insert(file.path.as_str(), IncomingFile::Bytes(bytes));
    }
    apply_remote_transfer_impl(share, remote, &file_data)
}

pub fn apply_remote_staged_transfer(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    files: &[CompletedFile],
) -> Result<ApplyOutcome> {
    remote.validate(share.share_id)?;
    validate_transfer_files_iter(files.iter().map(|file| &file.file), remote)?;
    let mut file_data = BTreeMap::new();
    for file in files {
        file_data.insert(
            file.file.path.as_str(),
            IncomingFile::Staged(file.staged_path.as_path()),
        );
    }
    let result = apply_remote_transfer_impl(share, remote, &file_data);
    if result.is_ok() {
        for file in files {
            let _ = fs::remove_file(&file.staged_path);
        }
    }
    result
}

pub fn apply_remote_transfer_impl(
    share: &Arc<ActiveShare>,
    remote: &Manifest,
    file_data: &BTreeMap<&str, IncomingFile<'_>>,
) -> Result<ApplyOutcome> {
    let config = share.config()?;
    let root = config_root(&config)?;
    let local_snapshot = share.manifest_snapshot()?;
    let local = &local_snapshot.manifest;

    let mut candidate = Cow::Borrowed(local);
    let mut hash_buffer = Vec::new();
    let mut pending_downloads = 0_usize;
    let mut applied_records = 0_usize;
    let mut deletions = remote
        .tombstones
        .iter()
        .filter(|(path, tombstone)| {
            remote_record_wins(
                local.record(path),
                Some(ManifestRecordRef::Tombstone(tombstone)),
            )
        })
        .collect::<Vec<_>>();
    deletions.sort_by(|(left, _), (right, _)| {
        manifest_path_depth(right)
            .cmp(&manifest_path_depth(left))
            .then_with(|| right.cmp(left))
    });
    for (path, tombstone) in deletions {
        remove_local_path(&root, path)?;
        let candidate = candidate.to_mut();
        candidate.entries.remove(path);
        candidate.directories.remove(path);
        candidate.symlinks.remove(path);
        candidate.tombstones.insert(path.clone(), tombstone.clone());
        applied_records = applied_records.saturating_add(1);
    }

    let mut directory_permissions = Vec::new();
    for (path, entry) in &remote.directories {
        if !remote_record_wins(
            local.record(path),
            Some(ManifestRecordRef::Directory(entry)),
        ) {
            continue;
        }
        ensure_local_directory(&root, path)?;
        let candidate = candidate.to_mut();
        candidate.entries.remove(path);
        candidate.symlinks.remove(path);
        candidate.tombstones.remove(path);
        candidate.directories.insert(path.clone(), entry.clone());
        directory_permissions.push((path, entry.permissions));
        applied_records = applied_records.saturating_add(1);
    }

    for (path, entry) in &remote.symlinks {
        if !remote_record_wins(local.record(path), Some(ManifestRecordRef::Symlink(entry))) {
            continue;
        }
        write_local_symlink(share, &root, path, &entry.target)?;
        let candidate = candidate.to_mut();
        candidate.entries.remove(path);
        candidate.directories.remove(path);
        candidate.tombstones.remove(path);
        candidate.symlinks.insert(path.clone(), entry.clone());
        applied_records = applied_records.saturating_add(1);
    }

    for (path, entry) in &remote.entries {
        if !remote_record_wins(local.record(path), Some(ManifestRecordRef::File(entry))) {
            continue;
        }
        if let Some(incoming) = file_data.get(path.as_str()) {
            match incoming {
                IncomingFile::Bytes(bytes) => {
                    write_local_file(share, &root, path, bytes, entry.permissions)?;
                }
                IncomingFile::Staged(staged_path) => {
                    write_local_staged_file(&root, path, staged_path, entry.permissions)?;
                }
            }
            let candidate = candidate.to_mut();
            candidate.directories.remove(path);
            candidate.entries.remove(path);
            candidate.tombstones.remove(path);
            candidate.symlinks.remove(path);
            candidate.entries.insert(path.clone(), entry.clone());
            applied_records = applied_records.saturating_add(1);
        } else {
            // Metadata-only changes, including chmod, do not need to retransmit unchanged
            // content. Keep the manifest conservative if the local file disappeared after its
            // most recent scan.
            let local_content_matches = local.entries.get(path).is_some_and(|local_entry| {
                local_entry.size == entry.size && local_entry.sha256 == entry.sha256
            });
            if local_content_matches
                && local_file_matches_entry(
                    &root,
                    path,
                    entry.size,
                    &entry.sha256,
                    &mut hash_buffer,
                )?
            {
                set_local_file_permissions(&root, path, entry.permissions)?;
                let candidate = candidate.to_mut();
                candidate.directories.remove(path);
                candidate.tombstones.remove(path);
                candidate.entries.insert(path.clone(), entry.clone());
                applied_records = applied_records.saturating_add(1);
            } else {
                pending_downloads = pending_downloads.saturating_add(1);
            }
        }
    }

    // Apply directory modes after their contents have been created. A remote directory can be
    // intentionally read-only, so applying it before the file phase could prevent the transfer.
    directory_permissions.sort_by(|(left, _), (right, _)| {
        manifest_path_depth(right)
            .cmp(&manifest_path_depth(left))
            .then_with(|| right.cmp(left))
    });
    for (path, permissions) in directory_permissions {
        set_local_directory_permissions(&root, path, permissions)?;
    }
    let unsupported_items = unsupported_symlink_count(&candidate);
    if let Cow::Owned(mut candidate) = candidate {
        candidate.scanned_at_ms = current_time_ms();
        candidate.validate(share.share_id)?;
        if candidate.entries != local.entries
            || candidate.directories != local.directories
            || candidate.symlinks != local.symlinks
            || candidate.tombstones != local.tombstones
        {
            observe_manifest_clock(share, &candidate)?;
            share.save_manifest(candidate)?;
        }
    }
    debug!(
        share_id = %share.share_id,
        applied_records,
        pending_downloads,
        unsupported_items,
        "remote transfer apply finished"
    );
    Ok(ApplyOutcome {
        pending_downloads,
        applied_records,
        unsupported_items,
    })
}

pub fn remote_record_wins(
    local: Option<ManifestRecordRef<'_>>,
    remote: Option<ManifestRecordRef<'_>>,
) -> bool {
    match (local, remote) {
        (None, Some(_)) => true,
        (Some(local), Some(remote)) => {
            remote.version() > local.version()
                || (remote.version() == local.version()
                    && remote.is_tombstone()
                    && !local.is_tombstone())
        }
        _ => false,
    }
}

pub fn observe_manifest_clock(share: &Arc<ActiveShare>, manifest: &Manifest) -> Result<()> {
    let mut clock = share.paths.load_clock(share.share_id)?;
    let now_ms = current_time_ms();
    for entry in manifest.entries.values() {
        clock.observe(entry.version, now_ms)?;
    }
    for entry in manifest.directories.values() {
        clock.observe(entry.version, now_ms)?;
    }
    for tombstone in manifest.tombstones.values() {
        clock.observe(tombstone.version, now_ms)?;
    }
    share.paths.save_clock(share.share_id, &clock)
}
