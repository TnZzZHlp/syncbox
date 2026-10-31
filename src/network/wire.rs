use std::collections::HashSet;

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::{
    frame,
    manifest::{Manifest, validate_manifest_path},
    types::{PROTOCOL_VERSION, ShareId, parse_endpoint_id},
};

use super::io::{RecvStream, SendStream};

pub const MAX_CONTROL_FRAME_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_TRANSFER_FILES: usize = 256;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) known_peers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMessage<M = Manifest> {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) manifest: M,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) download_paths: Vec<String>,
    pub(crate) download_resumes: Vec<TransferFile>,
    pub(crate) uploads: Vec<TransferFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferReady {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) uploads: Vec<TransferFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferResponse<M = Manifest, F = Vec<TransferFile>> {
    pub(crate) protocol_version: u16,
    pub(crate) share_id: ShareId,
    pub(crate) manifest: M,
    pub(crate) files: F,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferFile {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) offset: u64,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePayload {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) content: String,
}

pub fn validate_sync_request(request: &SyncRequest, share_id: ShareId) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION || request.share_id != share_id {
        bail!("sync request has an incompatible protocol or share ID");
    }
    validate_wire_peers(&request.known_peers)
}

pub fn validate_sync_response(response: &SyncResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("sync response has an incompatible protocol or share ID");
    }
    validate_wire_peers(&response.known_peers)
}

pub fn validate_manifest_message(
    message: &ManifestMessage,
    share_id: ShareId,
    expected_digest: &[u8; 32],
) -> Result<()> {
    if message.protocol_version != PROTOCOL_VERSION || message.share_id != share_id {
        bail!("manifest message has an incompatible protocol or share ID");
    }
    if message.manifest.sync_digest(share_id)? != *expected_digest {
        bail!("manifest message does not match its advertised digest");
    }
    Ok(())
}

pub fn validate_transfer_request(
    request: &TransferRequest,
    share_id: ShareId,
    manifest: &Manifest,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION || request.share_id != share_id {
        bail!("file transfer request has an incompatible protocol or share ID");
    }
    manifest.validate(share_id)?;
    validate_path_list(&request.download_paths)?;
    validate_transfer_files(&request.uploads, manifest)?;
    validate_transfer_file_shapes(&request.download_resumes)?;
    let requested_downloads = request.download_paths.iter().collect::<HashSet<_>>();
    for resume in &request.download_resumes {
        if !requested_downloads.contains(&resume.path) {
            bail!("network transfer resume path was not requested");
        }
    }
    Ok(())
}

pub fn validate_transfer_ready(
    ready: &TransferReady,
    share_id: ShareId,
    requested: &[TransferFile],
) -> Result<()> {
    if ready.protocol_version != PROTOCOL_VERSION || ready.share_id != share_id {
        bail!("file transfer ready message has an incompatible protocol or share ID");
    }
    validate_transfer_file_shapes(&ready.uploads)?;
    if ready.uploads.len() != requested.len() {
        bail!("file transfer ready message has an unexpected upload count");
    }
    for (actual, expected) in ready.uploads.iter().zip(requested) {
        if actual.path != expected.path
            || actual.sha256 != expected.sha256
            || actual.size != expected.size
        {
            bail!("file transfer ready message does not match the request");
        }
    }
    Ok(())
}

pub fn validate_transfer_response(response: &TransferResponse, share_id: ShareId) -> Result<()> {
    if response.protocol_version != PROTOCOL_VERSION || response.share_id != share_id {
        bail!("file transfer response has an incompatible protocol or share ID");
    }
    response.manifest.validate(share_id)?;
    validate_transfer_files(&response.files, &response.manifest)
}

pub fn validate_transfer_file_shapes(files: &[TransferFile]) -> Result<()> {
    if files.len() > MAX_TRANSFER_FILES {
        bail!("network transfer contains too many files");
    }
    let mut unique = HashSet::new();
    for file in files {
        validate_manifest_path(&file.path)?;
        validate_sha256(&file.sha256)?;
        if file.offset > file.size {
            bail!("network transfer resume offset exceeds file size");
        }
        if !unique.insert(&file.path) {
            bail!("network transfer contains duplicate file paths");
        }
    }
    Ok(())
}

pub fn validate_transfer_files(files: &[TransferFile], manifest: &Manifest) -> Result<()> {
    validate_transfer_file_shapes(files)?;
    for file in files {
        let entry = manifest
            .entries
            .get(&file.path)
            .ok_or_else(|| anyhow!("network transfer file is not present in its manifest"))?;
        if entry.sha256 != file.sha256 || entry.size != file.size {
            bail!("network transfer file metadata does not match its manifest");
        }
    }
    Ok(())
}

pub fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("network transfer hash must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

pub fn validate_wire_peers(peers: &[String]) -> Result<()> {
    if peers.len() > 256 {
        bail!("network peer list is too large");
    }
    let mut unique = HashSet::new();
    for peer in peers {
        parse_endpoint_id(peer)?;
        if !unique.insert(peer) {
            bail!("network peer list contains duplicates");
        }
    }
    Ok(())
}

pub fn validate_path_list(paths: &[String]) -> Result<()> {
    if paths.len() > MAX_TRANSFER_FILES {
        bail!("network file request contains too many paths");
    }
    let mut unique = HashSet::new();
    for path in paths {
        validate_manifest_path(path)?;
        if !unique.insert(path) {
            bail!("network file request contains duplicate paths");
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_file_payloads(files: &[FilePayload], manifest: &Manifest) -> Result<()> {
    if files.len() > MAX_TRANSFER_FILES {
        bail!("network transfer contains too many files");
    }
    let mut unique = HashSet::new();
    for file in files {
        validate_manifest_path(&file.path)?;
        if !unique.insert(&file.path) {
            bail!("network transfer contains duplicate file paths");
        }
        let entry = manifest
            .entries
            .get(&file.path)
            .ok_or_else(|| anyhow!("network file is not present in its manifest"))?;
        if entry.sha256 != file.sha256 {
            bail!("network file hash does not match its manifest");
        }
        let data = URL_SAFE_NO_PAD
            .decode(&file.content)
            .map_err(|_| anyhow!("network file payload is not valid base64url"))?;
        if URL_SAFE_NO_PAD.encode(&data) != file.content {
            bail!("network file payload must use canonical base64url encoding");
        }
        if data.len() as u64 != entry.size {
            bail!("network file payload has an invalid length");
        }
        let hash = hex::encode(Sha256::digest(&data));
        if hash != entry.sha256 {
            bail!("network file payload has an invalid hash");
        }
    }
    Ok(())
}

pub async fn write_json_frame<T: Serialize + Sync>(send: &mut SendStream, value: &T) -> Result<()> {
    frame::write_json(send, value, MAX_CONTROL_FRAME_BYTES).await
}

pub async fn read_json_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    frame::read_json(recv, MAX_CONTROL_FRAME_BYTES).await
}
