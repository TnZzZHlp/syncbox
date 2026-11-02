use super::*;

#[test]
fn scans_follow_events_with_a_bounded_full_scan_fallback() {
    let now = Instant::now();
    assert!(scan_due(None, now, true, false));
    assert!(!scan_due(
        Some(now),
        now + Duration::from_secs(59),
        true,
        false
    ));
    assert!(scan_due(Some(now), now + FULL_SCAN_INTERVAL, true, false));
    assert!(!scan_due(Some(now), now, true, true));
    assert!(scan_due(Some(now), now + SYNC_INTERVAL, true, true));
    assert!(!scan_due(
        Some(now),
        now + Duration::from_secs(4),
        false,
        false
    ));
    assert!(scan_due(Some(now), now + SYNC_INTERVAL, false, false));
}

#[test]
fn idle_peer_schedule_preserves_change_and_pending_work_latency() {
    let now = Instant::now();
    let mut schedule = PeerSchedule::default();
    assert!(schedule.due(now, 0));
    schedule.after_attempt(
        now,
        0,
        Some(&SyncOutcome {
            connected: true,
            ..SyncOutcome::default()
        }),
    );
    assert!(!schedule.due(now + Duration::from_secs(29), 0));
    assert!(schedule.due(now + IDLE_PEER_INTERVAL, 0));
    assert!(schedule.due(now, 1));

    schedule.after_attempt(
        now,
        1,
        Some(&SyncOutcome {
            connected: true,
            pending_downloads: 1,
            ..SyncOutcome::default()
        }),
    );
    assert!(!schedule.due(now + Duration::from_secs(4), 1));
    assert!(schedule.due(now + SYNC_INTERVAL, 1));
    schedule.after_attempt(
        now,
        1,
        Some(&SyncOutcome {
            connected: true,
            pending_updates: 1,
            ..SyncOutcome::default()
        }),
    );
    assert!(schedule.due(now + SYNC_INTERVAL, 1));
}

#[test]
fn offline_peer_schedule_backs_off_but_recovers_after_a_change() {
    let now = Instant::now();
    let mut schedule = PeerSchedule::default();
    for expected in [5, 10, 20, 30, 30] {
        schedule.after_attempt(now, 0, None);
        assert!(!schedule.due(now + Duration::from_secs(expected - 1), 0));
        assert!(schedule.due(now + Duration::from_secs(expected + 1), 0));
    }
    assert!(schedule.due(now, 1));
    schedule.after_attempt(
        now,
        1,
        Some(&SyncOutcome {
            connected: true,
            ..SyncOutcome::default()
        }),
    );
    schedule.after_attempt(now, 1, None);
    assert!(schedule.due(now + SYNC_INTERVAL + Duration::from_secs(1), 1));
}

#[test]
fn offline_peer_retries_preserve_an_idle_peers_success() {
    let now = Instant::now();
    let online = SecretKey::from_bytes(&[63; 32]).public();
    let offline = SecretKey::from_bytes(&[64; 32]).public();
    let mut schedules = HashMap::new();
    schedules
        .entry(online)
        .or_insert_with(PeerSchedule::default)
        .after_attempt(
            now,
            0,
            Some(&SyncOutcome {
                connected: true,
                ..SyncOutcome::default()
            }),
        );
    schedules
        .entry(offline)
        .or_insert_with(PeerSchedule::default)
        .after_attempt(now, 0, None);
    let mut candidates = vec![online, offline];
    select_due_peers(&mut candidates, &schedules, now + Duration::from_secs(6), 0);
    assert_eq!(candidates, vec![offline]);
    schedules
        .get_mut(&offline)
        .unwrap()
        .after_attempt(now + Duration::from_secs(6), 0, None);
    assert_eq!(summarize_peer_outcomes(&schedules).connected_peers, 1);
}

#[test]
fn peer_selection_reaches_nodes_beyond_the_first_four() {
    let peers: Vec<_> = (1..=6)
        .map(|seed| SecretKey::from_bytes(&[seed; 32]).public())
        .collect();
    let now = Instant::now();
    let mut schedules = HashMap::new();
    let mut first = peers.clone();
    select_due_peers(&mut first, &schedules, now, 0);
    for peer in first {
        let mut schedule = PeerSchedule::default();
        schedule.after_attempt(now, 0, None);
        schedules.insert(peer, schedule);
    }
    let mut next = peers.clone();
    select_due_peers(&mut next, &schedules, now + Duration::from_secs(31), 0);
    assert_eq!(&next[..2], &peers[4..]);
}

#[test]
fn peer_selection_preserves_priority_and_stable_ties_at_the_limit() {
    let peers: Vec<_> = (110..118)
        .map(|seed| SecretKey::from_bytes(&[seed; 32]).public())
        .collect();
    let now = Instant::now();
    let mut schedules = HashMap::new();
    for (index, &peer) in peers.iter().enumerate() {
        if index == 6 {
            continue;
        }
        let next_at = match index {
            3 => None,
            4 => Some(now + Duration::from_secs(1)),
            7 => Some(now.checked_sub(Duration::from_secs(3)).unwrap()),
            1 => Some(now.checked_sub(Duration::from_secs(1)).unwrap()),
            _ => Some(now.checked_sub(Duration::from_secs(2)).unwrap()),
        };
        schedules.insert(
            peer,
            PeerSchedule {
                next_at,
                last_attempted_generation: 1,
                ..PeerSchedule::default()
            },
        );
    }
    let mut selected = peers.clone();
    select_due_peers(&mut selected, &schedules, now, 1);
    assert_eq!(selected, [peers[3], peers[6], peers[7], peers[0]]);
}

#[test]
fn initial_sync_status_distinguishes_pending_work() {
    assert_eq!(
        initial_sync_status(&SyncOutcome {
            connected: true,
            ..SyncOutcome::default()
        }),
        InitialSyncStatus::Complete
    );
    assert_eq!(
        initial_sync_status(&SyncOutcome {
            connected: true,
            pending_downloads: 1,
            ..SyncOutcome::default()
        }),
        InitialSyncStatus::Pending
    );
    assert_eq!(
        initial_sync_status(&SyncOutcome {
            connected: true,
            unsupported_items: 1,
            ..SyncOutcome::default()
        }),
        InitialSyncStatus::Pending
    );
    assert_eq!(
        initial_sync_status(&SyncOutcome {
            connected: false,
            pending_updates: 1,
            ..SyncOutcome::default()
        }),
        InitialSyncStatus::Offline
    );
}

#[tokio::test]
async fn recovery_during_an_attempt_is_not_lost_when_that_attempt_finishes() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("shared");
    fs::create_dir(&root).unwrap();
    let peer = SecretKey::from_bytes(&[67; 32]).public();
    let share = active_share(&root, Manifest::empty(ShareId([68; 32]), 0), peer);
    share.record_peer_attempt(peer, 0, 0, None).await;
    assert!(!share.peer_schedule.lock().await[&peer].due(Instant::now(), 0));
    share.retry_peers().await;
    share.record_peer_attempt(peer, 0, 0, None).await;
    assert!(share.peer_schedule.lock().await[&peer].due(Instant::now(), 0));
}
