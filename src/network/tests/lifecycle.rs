use super::*;

#[tokio::test(flavor = "current_thread")]
async fn run_blocking_falls_back_without_panicking() {
    assert_eq!(run_blocking(|| 42), 42);
}

#[test]
fn read_events_do_not_rescan_but_write_events_and_overflow_do() {
    use notify::{
        Event, EventKind,
        event::{AccessKind, AccessMode, Flag},
    };

    let read = Event::new(EventKind::Access(AccessKind::Open(AccessMode::Read)));
    assert!(!scan_event_is_relevant(&read));
    let write = Event::new(EventKind::Access(AccessKind::Close(AccessMode::Write)));
    assert!(scan_event_is_relevant(&write));
    assert!(scan_event_is_relevant(&read.set_flag(Flag::Rescan)));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn file_changes_wake_a_watched_share() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("share");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([56; 32]);
    let endpoint = SecretKey::from_bytes(&[57; 32]).public();
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint);
    let registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(share_id, Arc::clone(&share))])),
    };
    let notify = Arc::new(Notify::new());
    let watchers = start_watchers(&registry, &notify);
    if watchers.is_empty() {
        assert!(!share.watcher_active.load(Ordering::Acquire));
        return; // Systems without available inotify watches use the five-second fallback.
    }
    share.scan_dirty.store(false, Ordering::Release);
    fs::write(root.join("changed.txt"), b"new content").unwrap();
    timeout(Duration::from_secs(3), async {
        while !share.scan_dirty.load(Ordering::Acquire) {
            notify.notified().await;
        }
    })
    .await
    .unwrap();
    assert!(share.watcher_active.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_interrupts_a_peer_wait_without_abandoning_the_cycle() {
    use iroh::{address_lookup::memory::MemoryLookup, endpoint::presets};

    let lookup = MemoryLookup::new();
    let client = Endpoint::builder(presets::Minimal)
        .address_lookup(lookup.clone())
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    lookup.add_endpoint_info(server.addr());
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("shared");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([65; 32]);
    let share = active_share(&root, Manifest::empty(share_id, 0), client.id());
    let mut peers = KnownPeers::empty();
    peers.add_or_touch(&server.id(), 0);
    share.paths.save_known_peers(share_id, &peers).unwrap();
    let registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(share_id, share)])),
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let receiver = server.clone();
    let handler = tokio::spawn(async move {
        let connection = receiver.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        recv.read_exact(&mut [0; CLIENT_HELLO_LENGTH])
            .await
            .unwrap();
        shutdown_tx.send(()).unwrap();
        connection.closed().await;
    });
    let result = timeout(
        Duration::from_secs(3),
        run_sync_cycle_until_shutdown(&client, &registry, async {
            shutdown_rx.await.context("shutdown sender dropped")
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result);
    handler.await.unwrap();
    server.close().await;
}

#[tokio::test]
async fn address_changes_wake_backed_off_peers() {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("shared");
    fs::create_dir(&root).unwrap();
    let share_id = ShareId([69; 32]);
    let share = active_share(&root, Manifest::empty(share_id, 0), endpoint.id());
    let peer = SecretKey::from_bytes(&[70; 32]).public();
    share.record_peer_attempt(peer, 0, 0, None).await;
    let registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(share_id, Arc::clone(&share))])),
    };
    let notify = Arc::new(Notify::new());
    let monitor = spawn_connectivity_monitor(endpoint.clone(), registry, Arc::clone(&notify));
    endpoint
        .add_external_addr("192.0.2.1:12345".parse().unwrap())
        .await;
    timeout(Duration::from_secs(3), notify.notified())
        .await
        .unwrap();
    assert!(share.peer_schedule.lock().await[&peer].due(Instant::now(), 0));
    endpoint.close().await;
    timeout(Duration::from_secs(3), monitor)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn incoming_handlers_are_drained_before_shutdown() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut handlers = tokio::task::JoinSet::new();
    handlers.spawn(async move {
        let _ = release_rx.await;
    });

    let mut drain = Box::pin(drain_incoming_handlers(&mut handlers));
    assert!(
        timeout(Duration::from_millis(10), &mut drain)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    drain.await;
    assert!(handlers.is_empty());
}
