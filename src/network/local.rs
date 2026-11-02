use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
#[cfg(windows)]
use tracing::warn;

use crate::{
    manifest::{path_for_manifest, validate_manifest_path},
    types::ShareConfig,
};

use super::{HASH_BUFFER_BYTES, state::ActiveShare};
pub fn config_root(config: &ShareConfig) -> Result<PathBuf> {
    let root = PathBuf::from(&config.local_directory);
    let metadata = fs::metadata(&root)
        .with_context(|| format!("unable to inspect local directory {}", root.display()))?;
    if !metadata.is_dir() {
        bail!(
            "registered local path {} is not a directory",
            root.display()
        );
    }
    fs::canonicalize(&root)
        .with_context(|| format!("unable to normalize local directory {}", root.display()))
}

pub fn safe_local_path(root: &Path, manifest_path: &str, writing: bool) -> Result<PathBuf> {
    let target = path_for_manifest(root, manifest_path)?;
    let mut parent = root.to_path_buf();
    let components = manifest_path.split('/').collect::<Vec<_>>();
    for component in &components[..components.len().saturating_sub(1)] {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("shared path contains a symbolic link: {}", parent.display())
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "shared path parent is not a directory: {}",
                    parent.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && writing => {
                fs::create_dir(&parent).with_context(|| {
                    format!("unable to create shared directory {}", parent.display())
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("unable to inspect {}", parent.display()));
            }
        }
    }
    Ok(target)
}

pub fn manifest_path_depth(path: &str) -> usize {
    path.bytes().filter(|byte| *byte == b'/').count() + 1
}

pub fn ensure_local_directory(root: &Path, manifest_path: &str) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            // A newer remote directory record may replace a local file at the same path. Do not
            // follow a symbolic link or replace another special file type.
            Ok(metadata) if metadata.is_file() => fs::remove_file(&target)
                .with_context(|| format!("unable to replace shared file {}", target.display()))?,
            Ok(_) => bail!("refusing to replace non-directory {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared directory {}", target.display())
                });
            }
        }
        fs::create_dir(&target)
            .with_context(|| format!("unable to create shared directory {}", target.display()))
    })
}

pub fn local_file_matches_entry(
    root: &Path,
    manifest_path: &str,
    expected_size: u64,
    expected_sha256: &str,
    buffer: &mut Vec<u8>,
) -> Result<bool> {
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("refusing to use symbolic link {}", target.display())
            }
            Ok(metadata) if metadata.is_file() && metadata.len() == expected_size => metadata,
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared file {}", target.display())
                });
            }
        };
        let before_modified = metadata.modified().ok();
        with_readable_file(&target, &metadata, || {
            let mut file = fs::File::open(&target)
                .with_context(|| format!("unable to read shared file {}", target.display()))?;
            let mut hasher = Sha256::new();
            if buffer.len() < HASH_BUFFER_BYTES {
                buffer.resize(HASH_BUFFER_BYTES, 0);
            }
            loop {
                let count = file
                    .read(&mut buffer[..HASH_BUFFER_BYTES])
                    .with_context(|| format!("unable to read shared file {}", target.display()))?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            let after = file
                .metadata()
                .with_context(|| format!("unable to inspect shared file {}", target.display()))?;
            Ok(after.is_file()
                && after.len() == expected_size
                && after.modified().ok() == before_modified
                && hex::encode(hasher.finalize()) == expected_sha256)
        })
    })
}

pub fn write_local_file(
    share: &Arc<ActiveShare>,
    root: &Path,
    manifest_path: &str,
    bytes: &[u8],
    permissions: Option<u16>,
) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            // Descendant tombstones are applied before files, so a newer remote file can replace
            // an emptied local directory without discarding untracked content.
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!("unable to replace shared directory {}", target.display())
            })?,
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => bail!("refusing to replace non-file {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared file {}", target.display())
                });
            }
        }
        // Transfer staging belongs in the registered share state directory, never in the synced tree.
        let temp = share.paths.share_tmp_dir(share.share_id).join(format!(
            "transfer-{}-{}.tmp",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        let result = (|| -> Result<()> {
            fs::write(&temp, bytes)
                .with_context(|| format!("unable to stage downloaded file {}", temp.display()))?;
            match fs::rename(&temp, &target) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                    // Application data and the shared directory may live on separate volumes. Fall
                    // back to a direct replacement rather than creating a program temporary file in
                    // the shared tree.
                    write_cross_device_target(&target, bytes, permissions)?;
                    fs::remove_file(&temp).with_context(|| {
                        format!("unable to remove transfer staging file {}", temp.display())
                    })?;
                    Ok(())
                }
                Err(_) if cfg!(windows) && target.exists() => {
                    // Windows rename does not consistently replace an existing file across supported
                    // filesystems. The target has already been checked not to be a symlink or directory.
                    fs::remove_file(&target).with_context(|| {
                        format!("unable to replace downloaded file {}", target.display())
                    })?;
                    fs::rename(&temp, &target).with_context(|| {
                        format!("unable to install downloaded file {}", target.display())
                    })
                }
                Err(error) => Err(error).with_context(|| {
                    format!("unable to install downloaded file {}", target.display())
                }),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result?;
        set_local_file_permissions(root, manifest_path, permissions)
    })
}

pub fn write_local_staged_file(
    root: &Path,
    manifest_path: &str,
    staged_path: &Path,
    permissions: Option<u16>,
) -> Result<()> {
    with_writable_parents(root, manifest_path, true, || {
        let target = safe_local_path(root, manifest_path, true)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!("unable to replace shared directory {}", target.display())
            })?,
            Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(&target)
                .with_context(|| {
                    format!("unable to replace shared symlink {}", target.display())
                })?,
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => bail!("refusing to replace non-file {}", target.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect shared path {}", target.display())
                });
            }
        }
        let staged_metadata = fs::symlink_metadata(staged_path)
            .with_context(|| format!("unable to inspect staged file {}", staged_path.display()))?;
        if !staged_metadata.is_file() || staged_metadata.file_type().is_symlink() {
            bail!("staged transfer is not a regular file");
        }
        match fs::rename(staged_path, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                with_writable_cross_device_target(&target, permissions, || {
                    fs::copy(staged_path, &target).map(|_| ()).with_context(|| {
                        format!("unable to install staged file {}", target.display())
                    })
                })?;
                fs::remove_file(staged_path).with_context(|| {
                    format!("unable to remove staged file {}", staged_path.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to install staged file {}", target.display())
                });
            }
        }
        set_local_file_permissions(root, manifest_path, permissions)
    })
}

pub fn write_local_symlink(
    share: &Arc<ActiveShare>,
    root: &Path,
    manifest_path: &str,
    target: &str,
) -> Result<()> {
    validate_manifest_path(manifest_path)?;
    if target.is_empty() || target.len() > 4096 || target.contains('\0') {
        bail!("remote symlink target is invalid");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        with_writable_parents(root, manifest_path, true, || {
            let local_target = safe_local_path(root, manifest_path, true)?;
            match fs::symlink_metadata(&local_target) {
                Ok(metadata) if metadata.is_dir() => {
                    fs::remove_dir(&local_target).with_context(|| {
                        format!(
                            "unable to replace shared directory {}",
                            local_target.display()
                        )
                    })?;
                }
                Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                    fs::remove_file(&local_target).with_context(|| {
                        format!("unable to replace shared path {}", local_target.display())
                    })?;
                }
                Ok(_) => bail!("refusing to replace non-file {}", local_target.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("unable to inspect shared path {}", local_target.display())
                    });
                }
            }
            let temporary = share.paths.share_tmp_dir(share.share_id).join(format!(
                "symlink-{}-{}.tmp",
                std::process::id(),
                rand::rng().random::<u64>()
            ));
            let result = (|| -> Result<()> {
                symlink(target, &temporary)
                    .with_context(|| format!("unable to stage symlink target {target}"))?;
                match fs::rename(&temporary, &local_target) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                        let _ = fs::remove_file(&temporary);
                        symlink(target, &local_target).with_context(|| {
                            format!("unable to install symlink {}", local_target.display())
                        })
                    }
                    Err(error) => Err(error).with_context(|| {
                        format!("unable to install symlink {}", local_target.display())
                    }),
                }
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
    }
    #[cfg(windows)]
    {
        let _ = target;
        warn!(
            share_id = %share.share_id,
            path = manifest_path,
            "recording remote symbolic link as unsupported on Windows"
        );
        // Match Syncthing: keep the remote link in local index state without creating a marker.
        // Removing a conflicting leaf is safe because remove_local_path never follows links and
        // refuses to remove non-empty directories.
        remove_local_path(root, manifest_path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (share, root, manifest_path, target);
        bail!("symbolic links are not supported on this platform")
    }
}

pub fn remove_local_path(root: &Path, manifest_path: &str) -> Result<()> {
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(&target)
                    .with_context(|| format!("unable to remove shared path {}", target.display()))
            }
            Ok(metadata) if metadata.is_dir() => fs::remove_dir(&target).with_context(|| {
                format!(
                    "unable to remove empty shared directory {}",
                    target.display()
                )
            }),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("unable to inspect {}", target.display()))
            }
        }
    })
}

pub fn set_local_file_permissions(
    root: &Path,
    manifest_path: &str,
    permissions: Option<u16>,
) -> Result<()> {
    let Some(permissions) = permissions else {
        return Ok(());
    };
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        set_permissions(&target, permissions, false)
    })
}

pub fn set_local_directory_permissions(
    root: &Path,
    manifest_path: &str,
    permissions: Option<u16>,
) -> Result<()> {
    let Some(permissions) = permissions else {
        return Ok(());
    };
    with_writable_parents(root, manifest_path, false, || {
        let target = safe_local_path(root, manifest_path, false)?;
        set_permissions(&target, permissions, true)
    })
}

#[cfg(unix)]
pub struct PermissionRestore {
    pub(crate) path: PathBuf,
    pub(crate) permissions: u32,
}

#[cfg(unix)]
pub fn with_writable_parents<T>(
    root: &Path,
    manifest_path: &str,
    create_missing_parents: bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    validate_manifest_path(manifest_path)?;
    let mut restores = Vec::new();
    let preparation = (|| -> Result<()> {
        prepare_directory_for_write(root, true, &mut restores)?;
        let components = manifest_path.split('/').collect::<Vec<_>>();
        let mut parent = root.to_path_buf();
        for component in &components[..components.len().saturating_sub(1)] {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(metadata) => {
                    prepare_inspected_directory_for_write(&parent, &metadata, true, &mut restores)?;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && create_missing_parents =>
                {
                    fs::create_dir(&parent).with_context(|| {
                        format!("unable to create shared directory {}", parent.display())
                    })?;
                    prepare_directory_for_write(&parent, false, &mut restores)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("unable to inspect {}", parent.display()));
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = preparation {
        let _ = restore_parent_permissions(restores);
        return Err(error);
    }
    let result = operation();
    let restore_result = restore_parent_permissions(restores);
    match (result, restore_result) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(unix)]
pub fn restore_parent_permissions(restores: Vec<PermissionRestore>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    restores.into_iter().rev().try_for_each(|restore| {
        fs::set_permissions(
            &restore.path,
            fs::Permissions::from_mode(restore.permissions),
        )
        .with_context(|| {
            format!(
                "unable to restore permissions on shared directory {}",
                restore.path.display()
            )
        })
    })
}

#[cfg(unix)]
pub fn prepare_directory_for_write(
    path: &Path,
    restore_existing_permissions: bool,
    restores: &mut Vec<PermissionRestore>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect shared directory {}", path.display()))?;
    prepare_inspected_directory_for_write(path, &metadata, restore_existing_permissions, restores)
}

#[cfg(unix)]
fn prepare_inspected_directory_for_write(
    path: &Path,
    metadata: &fs::Metadata,
    restore_existing_permissions: bool,
    restores: &mut Vec<PermissionRestore>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if metadata.file_type().is_symlink() {
        bail!("shared path contains a symbolic link: {}", path.display());
    }
    if !metadata.is_dir() {
        bail!("shared path parent is not a directory: {}", path.display());
    }
    let permissions = metadata.permissions().mode() & 0o7777;
    if permissions & 0o300 == 0o300 {
        return Ok(());
    }
    match fs::set_permissions(path, fs::Permissions::from_mode(permissions | 0o300)) {
        Ok(()) => {
            if restore_existing_permissions {
                restores.push(PermissionRestore {
                    path: path.to_path_buf(),
                    permissions,
                });
            }
        }
        Err(_error) if directory_mode_allows_non_owner_writes(permissions) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "unable to make shared directory writable {}",
                    path.display()
                )
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn directory_mode_allows_non_owner_writes(permissions: u32) -> bool {
    [0o030, 0o003]
        .into_iter()
        .any(|required| permissions & required == required)
}

#[cfg(not(unix))]
pub fn with_writable_parents<T>(
    _root: &Path,
    _manifest_path: &str,
    _create_missing_parents: bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

#[cfg(unix)]
pub fn with_readable_file<T>(
    target: &Path,
    metadata: &fs::Metadata,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::os::unix::fs::PermissionsExt as _;

    if metadata.file_type().is_symlink() {
        bail!("refusing to read symbolic link {}", target.display());
    }
    if !metadata.is_file() {
        bail!("shared path is not a regular file: {}", target.display());
    }
    let permissions = metadata.permissions().mode() & 0o7777;
    let restore_permissions = if permissions & 0o400 == 0 {
        match fs::set_permissions(target, fs::Permissions::from_mode(permissions | 0o400)) {
            Ok(()) => Some(permissions),
            Err(_) if permissions & 0o044 != 0 => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to make shared file readable {}", target.display())
                });
            }
        }
    } else {
        None
    };
    let result = operation();
    let restore_result = restore_permissions.map_or_else(
        || Ok(()),
        |permissions| {
            fs::set_permissions(target, fs::Permissions::from_mode(permissions)).with_context(
                || {
                    format!(
                        "unable to restore permissions on shared file {}",
                        target.display()
                    )
                },
            )
        },
    );
    match (result, restore_result) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(not(unix))]
pub fn with_readable_file<T>(
    _target: &Path,
    _metadata: &fs::Metadata,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

#[cfg(unix)]
pub fn set_permissions(target: &Path, permissions: u16, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(target)
        .with_context(|| format!("unable to inspect shared path {}", target.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing to change permissions on symbolic link {}",
            target.display()
        );
    }
    if directory != metadata.is_dir() || (!directory && !metadata.is_file()) {
        bail!("shared path has an unexpected type: {}", target.display());
    }
    if metadata.permissions().mode() & 0o7777 == u32::from(permissions) {
        return Ok(());
    }
    fs::set_permissions(target, fs::Permissions::from_mode(u32::from(permissions)))
        .with_context(|| format!("unable to set permissions on {}", target.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub const fn set_permissions(_target: &Path, _permissions: u16, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn with_writable_cross_device_target<T>(
    target: &Path,
    final_permissions: Option<u16>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::os::unix::fs::PermissionsExt as _;

    let restore_permissions = match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to replace symbolic link {}", target.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("refusing to replace non-file {}", target.display())
        }
        Ok(metadata) => {
            let permissions = metadata.permissions().mode() & 0o7777;
            if permissions & 0o200 == 0 {
                match fs::set_permissions(target, fs::Permissions::from_mode(permissions | 0o200)) {
                    Ok(()) => Some(permissions),
                    Err(_) if permissions & 0o022 != 0 => None,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("unable to make shared file writable {}", target.display())
                        });
                    }
                }
            } else {
                None
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("unable to inspect shared file {}", target.display()));
        }
    };
    let operation_result = operation();
    if (operation_result.is_err() || final_permissions.is_none())
        && let Some(permissions) = restore_permissions
    {
        fs::set_permissions(target, fs::Permissions::from_mode(permissions)).with_context(
            || {
                format!(
                    "unable to restore permissions on shared file {}",
                    target.display()
                )
            },
        )?;
    }
    operation_result
}

#[cfg(not(unix))]
pub fn with_writable_cross_device_target<T>(
    _target: &Path,
    _final_permissions: Option<u16>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

pub fn write_cross_device_target(
    target: &Path,
    bytes: &[u8],
    final_permissions: Option<u16>,
) -> Result<()> {
    with_writable_cross_device_target(target, final_permissions, || {
        fs::write(target, bytes)
            .with_context(|| format!("unable to install downloaded file {}", target.display()))
    })
}
