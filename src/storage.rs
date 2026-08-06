use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use directories_next::BaseDirs;
use fs4::{FileExt, TryLockError};
use rand::Rng as _;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    manifest::Manifest,
    types::{ClockState, KnownPeers, RuntimeStatus, ShareConfig, ShareId},
};

const SMALL_STATE_MAX_BYTES: u64 = 1024 * 1024;
const MANIFEST_MAX_BYTES: u64 = 64 * 1024 * 1024;
const IDENTITY_KEY_BYTES: u64 = 32;

#[derive(Clone, Debug)]
pub struct DataPaths {
    root: PathBuf,
}

impl DataPaths {
    pub fn discover() -> Result<Self> {
        if let Some(override_path) = std::env::var_os("SYNCBOX_DATA_DIR") {
            let root = PathBuf::from(override_path);
            if !root.is_absolute() {
                bail!("SYNCBOX_DATA_DIR must be an absolute path");
            }
            return Ok(Self { root });
        }

        let base_dirs = BaseDirs::new().ok_or_else(|| {
            anyhow!("the operating system did not provide a local application data directory")
        })?;
        Ok(Self {
            // BaseDirs supplies the platform data root. Syncbox never constructs a home path.
            root: base_dirs.data_local_dir().join("syncbox"),
        })
    }

    #[cfg(test)]
    pub const fn from_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identity_dir(&self) -> PathBuf {
        self.root.join("identity")
    }

    pub fn identity_key(&self) -> PathBuf {
        self.identity_dir().join("device.key")
    }

    pub fn shares_dir(&self) -> PathBuf {
        self.root.join("shares")
    }

    pub fn locks_dir(&self) -> PathBuf {
        self.root.join("locks")
    }

    pub fn share_dir(&self, share_id: ShareId) -> PathBuf {
        self.shares_dir().join(share_id.to_string())
    }

    pub fn share_config(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("config.json")
    }

    pub fn share_manifest(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("manifest.json")
    }

    pub fn share_clock(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("clock.json")
    }

    pub fn share_known_peers(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("known_peers.json")
    }

    pub fn share_runtime_status(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("runtime-status.json")
    }

    pub fn share_tmp_dir(&self, share_id: ShareId) -> PathBuf {
        self.share_dir(share_id).join("tmp")
    }

    pub fn share_lock(&self, share_id: ShareId) -> PathBuf {
        self.locks_dir().join(format!("{share_id}.lock"))
    }

    pub fn registry_lock(&self) -> PathBuf {
        self.locks_dir().join("registry.lock")
    }

    pub fn identity_lock(&self) -> PathBuf {
        self.locks_dir().join("identity.lock")
    }

    pub fn device_run_lock(&self) -> PathBuf {
        self.locks_dir().join("device-run.lock")
    }

    pub fn ensure_layout(&self) -> Result<()> {
        create_secure_dir(&self.root)?;
        create_secure_dir(&self.identity_dir())?;
        create_secure_dir(&self.shares_dir())?;
        create_secure_dir(&self.locks_dir())?;
        Ok(())
    }

    pub fn ensure_share_layout(&self, share_id: ShareId) -> Result<()> {
        self.ensure_layout()?;
        create_secure_dir(&self.share_dir(share_id))?;
        create_secure_dir(&self.share_tmp_dir(share_id))?;
        create_lock_file(&self.share_lock(share_id))?;
        Ok(())
    }

    /// Publishes a complete new share directory only after every state file has been persisted.
    /// Interrupted registration leaves an ignored staging directory instead of a half-registered
    /// share visible to status or run.
    pub fn create_share_state(
        &self,
        config: &ShareConfig,
        manifest: &Manifest,
        clock: &ClockState,
        peers: &KnownPeers,
        runtime: &RuntimeStatus,
    ) -> Result<()> {
        let share_id = config.share_id;
        config.validate(share_id)?;
        manifest.validate(share_id)?;
        clock.validate()?;
        peers.validate()?;
        runtime.validate()?;
        self.ensure_layout()?;
        let target = self.share_dir(share_id);
        if target.exists() {
            bail!(
                "registered share directory {} already exists",
                target.display()
            );
        }
        let staging = self.shares_dir().join(format!(
            ".{}-{}-{}.tmp",
            share_id,
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        create_secure_dir(&staging)?;
        create_secure_dir(&staging.join("tmp"))?;
        let write_result = (|| -> Result<()> {
            atomic_write_json(&staging.join("config.json"), config, true)?;
            atomic_write_json(&staging.join("manifest.json"), manifest, false)?;
            atomic_write_json(&staging.join("clock.json"), clock, true)?;
            atomic_write_json(&staging.join("known_peers.json"), peers, false)?;
            atomic_write_json(&staging.join("runtime-status.json"), runtime, false)?;
            fs::rename(&staging, &target).with_context(|| {
                format!(
                    "unable to publish registered share directory {}",
                    target.display()
                )
            })?;
            sync_parent_directory(&self.shares_dir())?;
            create_lock_file(&self.share_lock(share_id))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        write_result
    }

    pub fn acquire_registry_lock(&self) -> Result<File> {
        self.ensure_layout()?;
        acquire_lock(&self.registry_lock())
    }

    pub fn acquire_identity_lock(&self) -> Result<File> {
        self.ensure_layout()?;
        acquire_lock(&self.identity_lock())
    }

    pub fn acquire_device_run_lock(&self) -> Result<File> {
        self.ensure_layout()?;
        acquire_lock(&self.device_run_lock())
    }

    pub fn try_acquire_device_run_lock(&self) -> Result<Option<File>> {
        self.ensure_layout()?;
        try_acquire_lock(&self.device_run_lock())
    }

    pub fn acquire_share_lock(&self, share_id: ShareId) -> Result<File> {
        self.ensure_layout()?;
        acquire_lock(&self.share_lock(share_id))
    }

    pub fn try_acquire_share_lock(&self, share_id: ShareId) -> Result<Option<File>> {
        self.ensure_layout()?;
        try_acquire_lock(&self.share_lock(share_id))
    }

    /// Returns whether another process currently owns a share lock without creating data files.
    pub fn share_lock_is_held(&self, share_id: ShareId) -> Result<bool> {
        let path = self.share_lock(share_id);
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("unable to inspect lock file {}", path.display()));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("unable to open lock file {}", path.display()))?;
        match FileExt::try_lock(&file) {
            Ok(()) => {
                drop(file);
                Ok(false)
            }
            Err(TryLockError::WouldBlock) => Ok(true),
            Err(TryLockError::Error(error)) => Err(error)
                .with_context(|| format!("unable to inspect lock file {}", path.display())),
        }
    }

    pub fn list_share_ids(&self) -> Result<Vec<ShareId>> {
        let directory = self.shares_dir();
        match fs::metadata(&directory) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => bail!(
                "registered shares path {} is not a directory",
                directory.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "unable to inspect registered shares directory {}",
                        directory.display()
                    )
                });
            }
        }
        let mut share_ids = Vec::new();
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "unable to list registered shares in {}",
                directory.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "unable to inspect registered shares in {}",
                    directory.display()
                )
            })?;
            let file_type = entry
                .file_type()
                .context("unable to inspect registered share entry")?;
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Ok(share_id) = ShareId::parse(name) {
                share_ids.push(share_id);
            }
        }
        share_ids.sort_unstable();
        Ok(share_ids)
    }

    pub fn share_exists(&self, share_id: ShareId) -> bool {
        self.share_dir(share_id).is_dir()
    }

    pub fn load_identity_bytes(&self) -> Result<Option<[u8; 32]>> {
        let path = self.identity_key();
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect device identity {}", path.display())
                });
            }
        }
        let data = read_bounded(&path, IDENTITY_KEY_BYTES)?;
        if data.len() as u64 != IDENTITY_KEY_BYTES {
            bail!("device identity file is malformed; expected exactly 32 bytes");
        }
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| anyhow!("device identity file is malformed"))?;
        Ok(Some(bytes))
    }

    pub fn save_identity_bytes(&self, bytes: &[u8; 32]) -> Result<()> {
        self.ensure_layout()?;
        atomic_write(&self.identity_key(), bytes, true)
    }

    pub fn load_config(&self, share_id: ShareId) -> Result<ShareConfig> {
        let config: ShareConfig = read_json(&self.share_config(share_id), SMALL_STATE_MAX_BYTES)?;
        config.validate(share_id)?;
        Ok(config)
    }

    pub fn save_config(&self, config: &ShareConfig) -> Result<()> {
        config.validate(config.share_id)?;
        atomic_write_json(&self.share_config(config.share_id), config, true)
    }

    pub fn load_manifest(&self, share_id: ShareId) -> Result<Manifest> {
        let manifest: Manifest = read_json(&self.share_manifest(share_id), MANIFEST_MAX_BYTES)?;
        manifest.validate(share_id)?;
        Ok(manifest)
    }

    pub fn save_manifest(&self, manifest: &Manifest) -> Result<()> {
        manifest.validate(manifest.share_id)?;
        atomic_write_json(&self.share_manifest(manifest.share_id), manifest, false)
    }

    pub fn load_clock(&self, share_id: ShareId) -> Result<ClockState> {
        let clock: ClockState = read_json(&self.share_clock(share_id), SMALL_STATE_MAX_BYTES)?;
        clock.validate()?;
        Ok(clock)
    }

    pub fn save_clock(&self, share_id: ShareId, clock: &ClockState) -> Result<()> {
        clock.validate()?;
        atomic_write_json(&self.share_clock(share_id), clock, true)
    }

    pub fn load_known_peers(&self, share_id: ShareId) -> Result<KnownPeers> {
        let peers: KnownPeers =
            read_json(&self.share_known_peers(share_id), SMALL_STATE_MAX_BYTES)?;
        peers.validate()?;
        Ok(peers)
    }

    pub fn save_known_peers(&self, share_id: ShareId, peers: &KnownPeers) -> Result<()> {
        peers.validate()?;
        atomic_write_json(&self.share_known_peers(share_id), peers, false)
    }

    pub fn load_runtime_status(&self, share_id: ShareId) -> Result<Option<RuntimeStatus>> {
        let path = self.share_runtime_status(share_id);
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect runtime status {}", path.display())
                });
            }
        }
        let status: RuntimeStatus = read_json(&path, SMALL_STATE_MAX_BYTES)?;
        status.validate()?;
        Ok(Some(status))
    }

    pub fn save_runtime_status(&self, share_id: ShareId, status: &RuntimeStatus) -> Result<()> {
        status.validate()?;
        atomic_write_json(&self.share_runtime_status(share_id), status, false)
    }

    pub fn read_file_bounded(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        read_bounded(path, max_bytes)
    }

    pub fn write_file_atomically(&self, path: &Path, bytes: &[u8], private: bool) -> Result<()> {
        atomic_write(path, bytes, private)
    }
}

fn create_secure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("unable to create data directory {}", path.display()))?;
    set_dir_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("unable to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn create_lock_file(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("unable to create lock file {}", path.display()))?;
    set_file_permissions(&file, true)?;
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("unable to open lock file {}", path.display()))?;
    FileExt::lock(&file).with_context(|| format!("unable to lock {}", path.display()))?;
    Ok(file)
}

fn try_acquire_lock(path: &Path) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("unable to open lock file {}", path.display()))?;
    match FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("unable to lock {}", path.display()))
        }
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("unable to inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{} exceeds the maximum supported size of {} bytes",
            path.display(),
            max_bytes
        );
    }
    let mut file =
        File::open(path).with_context(|| format!("unable to open {}", path.display()))?;
    let capacity = usize::try_from(metadata.len())
        .with_context(|| format!("{} is too large for this platform", path.display()))?;
    let mut data = Vec::with_capacity(capacity);
    file.read_to_end(&mut data)
        .with_context(|| format!("unable to read {}", path.display()))?;
    if data.len() as u64 > max_bytes {
        bail!("{} grew beyond its maximum supported size", path.display());
    }
    Ok(data)
}

fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T> {
    let bytes = read_bounded(path, max_bytes)?;
    serde_json::from_slice(&bytes).with_context(|| format!("unable to parse {}", path.display()))
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).context("unable to serialize persistent state")?;
    bytes.push(b'\n');
    atomic_write(path, &bytes, private)
}

fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("persistent state path has no parent"))?;
    create_secure_dir(parent)?;

    let suffix: u64 = rand::rng().random();
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("syncbox-state"),
        std::process::id(),
        suffix
    ));

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| {
                format!(
                    "unable to create temporary state file {}",
                    temporary.display()
                )
            })?;
        set_file_permissions(&file, private)?;
        file.write_all(bytes).with_context(|| {
            format!(
                "unable to write temporary state file {}",
                temporary.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "unable to flush temporary state file {}",
                temporary.display()
            )
        })?;
        drop(file);
        atomic_replace(&temporary, path).with_context(|| {
            format!(
                "unable to atomically replace persistent state {}",
                path.display()
            )
        })?;
        sync_parent_directory(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(unix)]
fn set_file_permissions(file: &File, _private: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("unable to set persistent state file permissions")
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &File, _private: bool) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(temporary: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(temporary, target)
}

#[cfg(windows)]
fn atomic_replace(temporary: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary_wide = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // Both paths include a trailing NUL and remain alive through the system call.
    if unsafe { MoveFileExW(temporary_wide.as_ptr(), target_wide.as_ptr(), flags) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("unable to open state directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("unable to flush state directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn state_file_replacement_keeps_the_latest_complete_value() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        paths.ensure_layout().unwrap();
        let path = paths.root().join("state.json");
        paths.write_file_atomically(&path, b"first", true).unwrap();
        paths.write_file_atomically(&path, b"second", true).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"second");
    }

    #[test]
    fn invalid_share_directories_are_not_registered_shares() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        paths.ensure_layout().unwrap();
        fs::create_dir(paths.shares_dir().join("not-a-share")).unwrap();
        assert!(paths.list_share_ids().unwrap().is_empty());
    }
}
