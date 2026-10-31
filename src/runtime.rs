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
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::types::RuntimeState;

    #[test]
    fn unchanged_updates_leave_refreshing_to_the_heartbeat() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        let share_id = ShareId::random();
        let mut cache = RuntimeStatusCache::default();
        cache
            .update(&paths, share_id, 10, false, |_, _| {})
            .unwrap();
        cache
            .update(&paths, share_id, 11, false, |_, _| {})
            .unwrap();
        assert_eq!(
            paths
                .load_runtime_status(share_id)
                .unwrap()
                .unwrap()
                .heartbeat_at_ms,
            10
        );
        cache.update(&paths, share_id, 12, true, |_, _| {}).unwrap();
        assert_eq!(
            paths
                .load_runtime_status(share_id)
                .unwrap()
                .unwrap()
                .heartbeat_at_ms,
            12
        );
    }

    #[test]
    fn state_changes_are_persisted_without_waiting_for_a_heartbeat() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        let share_id = ShareId::random();
        let mut cache = RuntimeStatusCache::default();
        cache
            .update(&paths, share_id, 10, false, |_, _| {})
            .unwrap();
        cache
            .update(&paths, share_id, 11, false, |status, _| {
                status.state = RuntimeState::Running;
            })
            .unwrap();
        let persisted = paths.load_runtime_status(share_id).unwrap().unwrap();
        assert_eq!(persisted.state, RuntimeState::Running);
        assert_eq!(persisted.heartbeat_at_ms, 11);
    }

    #[test]
    fn failed_status_writes_invalidate_the_cache() {
        let temporary = TempDir::new().unwrap();
        let paths = DataPaths::from_root(temporary.path().join("data"));
        let share_id = ShareId::random();
        let mut cache = RuntimeStatusCache::default();
        cache
            .update(&paths, share_id, 10, false, |_, _| {})
            .unwrap();
        let path = paths.share_runtime_status(share_id);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(
            cache
                .update(&paths, share_id, 11, false, |status, _| {
                    status.state = RuntimeState::Running;
                })
                .is_err()
        );
        fs::remove_dir(&path).unwrap();
        let mut restored = RuntimeStatus::stopped(12);
        restored.pending_updates = 7;
        paths.save_runtime_status(share_id, &restored).unwrap();
        cache.update(&paths, share_id, 13, true, |_, _| {}).unwrap();
        let persisted = paths.load_runtime_status(share_id).unwrap().unwrap();
        assert_eq!(persisted.pending_updates, 7);
        assert_eq!(persisted.state, RuntimeState::Stopped);
    }
}
