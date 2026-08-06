use anyhow::Result;
use iroh::{EndpointId, SecretKey};

use crate::storage::DataPaths;

#[derive(Clone)]
pub struct DeviceIdentity {
    secret_key: SecretKey,
}

impl DeviceIdentity {
    pub fn endpoint_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key.clone()
    }
}

pub fn load_or_create(paths: &DataPaths) -> Result<DeviceIdentity> {
    let _identity_lock = paths.acquire_identity_lock()?;
    if let Some(bytes) = paths.load_identity_bytes()? {
        return Ok(DeviceIdentity {
            secret_key: SecretKey::from_bytes(&bytes),
        });
    }
    let secret_key = SecretKey::generate();
    paths.save_identity_bytes(&secret_key.to_bytes())?;
    Ok(DeviceIdentity { secret_key })
}

pub fn load_existing(paths: &DataPaths) -> Result<Option<DeviceIdentity>> {
    paths.load_identity_bytes()?.map_or_else(
        || Ok(None),
        |bytes| {
            Ok(Some(DeviceIdentity {
                secret_key: SecretKey::from_bytes(&bytes),
            }))
        },
    )
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn identity_is_stable_after_reload() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        let first = load_or_create(&paths).unwrap().endpoint_id();
        let second = load_or_create(&paths).unwrap().endpoint_id();
        assert_eq!(first, second);
    }
}
