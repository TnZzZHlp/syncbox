//! Bounded reads and atomic, privately-permissioned state writes.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use rand::RngExt as _;
use serde::{Serialize, de::DeserializeOwned};

pub(super) fn create_secure_dir(path: &Path) -> Result<()> {
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
#[allow(clippy::unnecessary_wraps)]
const fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
pub(super) fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
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

pub(super) fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T> {
    let bytes = read_bounded(path, max_bytes)?;
    serde_json::from_slice(&bytes).with_context(|| format!("unable to parse {}", path.display()))
}

pub(super) fn atomic_write_json<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<()> {
    atomic_write_with(path, private, |file| {
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        serde_json::to_writer(&mut writer, value)
            .context("unable to serialize persistent state")?;
        writer.write_all(b"\n")?;
        writer
            .flush()
            .context("unable to flush persistent state buffer")
    })
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    atomic_write_with(path, private, |file| {
        file.write_all(bytes)
            .context("unable to write persistent state")
    })
}

pub(super) fn atomic_write_with(
    path: &Path,
    private: bool,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
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
        write(&mut file).with_context(|| {
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
pub(super) fn set_file_permissions(file: &File, _private: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("unable to set persistent state file permissions")
}
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(super) const fn set_file_permissions(_file: &File, _private: bool) -> Result<()> {
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
    #[allow(unsafe_code)]
    let result = unsafe { MoveFileExW(temporary_wide.as_ptr(), target_wide.as_ptr(), flags) };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("unable to open state directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("unable to flush state directory {}", parent.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(super) const fn sync_parent_directory(_parent: &Path) -> Result<()> {
    Ok(())
}
