//! Advisory lock files.

use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use anyhow::{Context, Result};
use fs4::{FileExt, TryLockError};

use super::atomic::set_file_permissions;

pub(super) fn create_lock_file(path: &Path) -> Result<()> {
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

pub(super) fn acquire_lock(path: &Path) -> Result<File> {
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

pub(super) fn try_acquire_lock(path: &Path) -> Result<Option<File>> {
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
