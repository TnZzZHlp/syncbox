use std::{
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};

pub fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn validate_manifest_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.contains('\\') || value.contains('\0') {
        bail!("manifest path is invalid");
    }
    let path = Path::new(value);
    if path.is_absolute() {
        bail!("manifest path must be relative");
    }
    let components = path.components();
    let mut count = 0_usize;
    for component in components {
        match component {
            Component::Normal(component) => {
                if component.is_empty() || component.to_str().is_none() {
                    bail!("manifest path contains an invalid component");
                }
                count += 1;
            }
            _ => bail!("manifest path contains an unsafe component"),
        }
    }
    if count == 0 {
        bail!("manifest path is empty");
    }
    Ok(())
}

pub fn path_for_manifest(root: &Path, manifest_path: &str) -> Result<PathBuf> {
    validate_manifest_path(manifest_path)?;
    let mut path = root.to_path_buf();
    for component in manifest_path.split('/') {
        path.push(component);
    }
    Ok(path)
}

pub fn relative_manifest_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("scanned path {} is outside its root", path.display()))?;
    let mut value = String::with_capacity(relative.as_os_str().len());
    for component in relative.components() {
        match component {
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| anyhow!("local file name is not valid UTF-8"))?;
                if component.is_empty() || component.contains('\\') || component.contains('/') {
                    bail!("local file name cannot be represented safely in a manifest");
                }
                if !value.is_empty() {
                    value.push('/');
                }
                value.push_str(component);
            }
            _ => bail!("local file path cannot be represented safely in a manifest"),
        }
    }
    validate_manifest_path(&value)?;
    Ok(value)
}
