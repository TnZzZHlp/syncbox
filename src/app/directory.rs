//! Shared-directory normalization and isolation checks.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};

use crate::types::{ShareConfig, validate_share_name};

pub fn canonical_or_projected_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("unable to determine the current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let mut missing_tail = Vec::new();
    let mut existing = normalized.as_path();
    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| anyhow!("path has no existing ancestor"))?;
        missing_tail.push(name.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| anyhow!("path has no existing ancestor"))?;
    }
    let mut resolved = fs::canonicalize(existing)
        .with_context(|| format!("unable to normalize path {}", existing.display()))?;
    for component in missing_tail.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub fn normalize_local_directory(requested_directory: &Path) -> Result<PathBuf> {
    if requested_directory.exists() {
        let metadata = fs::metadata(requested_directory).with_context(|| {
            format!(
                "unable to inspect local directory {}",
                requested_directory.display()
            )
        })?;
        if !metadata.is_dir() {
            bail!("{} is not a directory", requested_directory.display());
        }
    } else {
        fs::create_dir_all(requested_directory).with_context(|| {
            format!(
                "unable to create local directory {}",
                requested_directory.display()
            )
        })?;
    }
    let directory = fs::canonicalize(requested_directory).with_context(|| {
        format!(
            "unable to normalize local directory {}",
            requested_directory.display()
        )
    })?;
    if directory.to_str().is_none() {
        bail!("local directory path is not valid UTF-8");
    }
    Ok(directory)
}

pub fn path_to_config_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("local directory path is not valid UTF-8"))
}

pub fn config_directory(config: &ShareConfig) -> Result<PathBuf> {
    let path = PathBuf::from(&config.local_directory);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("unable to inspect local directory {}", path.display()))?;
    if !metadata.is_dir() {
        bail!(
            "registered local path {} is not a directory",
            path.display()
        );
    }
    fs::canonicalize(&path)
        .with_context(|| format!("unable to normalize local directory {}", path.display()))
}

pub fn determine_share_name(
    local_directory: &Path,
    requested_name: Option<&str>,
) -> Result<String> {
    let name = requested_name.map_or_else(
        || {
            local_directory
                .file_name()
                .and_then(|component| component.to_str())
                .filter(|component| !component.is_empty())
                .unwrap_or("share")
                .to_owned()
        },
        std::borrow::ToOwned::to_owned,
    );
    validate_share_name(&name)?;
    Ok(name)
}
#[cfg(target_os = "linux")]
pub fn process_alive(process_id: u32) -> bool {
    if process_id == 0 {
        return false;
    }
    Path::new("/proc").join(process_id.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) const fn process_alive(process_id: u32) -> bool {
    if process_id == 0 {
        false
    } else {
        // The lock plus a fresh heartbeat remains authoritative on platforms where the process
        // table is not exposed through a portable standard-library API.
        true
    }
}
