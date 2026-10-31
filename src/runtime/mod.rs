use anyhow::Result;

use crate::{
    storage::DataPaths,
    types::{RuntimeStatus, ShareId},
};

#[derive(Default)]
pub struct RuntimeStatusCache {
    persisted: Option<RuntimeStatus>,
}

impl RuntimeStatusCache {
    pub fn update<F>(
        &mut self,
        paths: &DataPaths,
        share_id: ShareId,
        now_ms: u64,
        heartbeat: bool,
        update: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut RuntimeStatus, u64),
    {
        let previous = match self.persisted.take() {
            Some(status) => status,
            None => paths
                .load_runtime_status(share_id)?
                .unwrap_or_else(|| RuntimeStatus::stopped(now_ms)),
        };
        let mut status = previous.clone();
        if status.process_id == 0 {
            status.process_id = std::process::id();
            status.started_at_ms = now_ms;
        }
        update(&mut status, now_ms);
        if !heartbeat && status == previous {
            self.persisted = Some(previous);
            return Ok(());
        }
        status.heartbeat_at_ms = now_ms;
        paths.save_runtime_status(share_id, &status)?;
        self.persisted = Some(status);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
