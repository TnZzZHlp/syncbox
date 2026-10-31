use super::*;
use crate::network::{peer_sessions::refresh_peer_status, workers::run_share_workers};

#[tokio::test]
async fn an_old_peer_success_does_not_confirm_new_local_changes() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("shared");
    fs::create_dir(&root).unwrap();
    let local = SecretKey::from_bytes(&[76; 32]).public();
    let peer = SecretKey::from_bytes(&[77; 32]).public();
    let share_id = ShareId([78; 32]);
    let share = active_share(&root, Manifest::empty(share_id, 0), local);
    share
        .record_peer_attempt(
            peer,
            0,
            0,
            Some(&SyncOutcome {
                connected: true,
                ..SyncOutcome::default()
            }),
        )
        .await;
    fs::write(root.join("changed.txt"), b"changed").unwrap();
    scan_and_save(&share, &share.config().unwrap()).unwrap();
    refresh_peer_status(&share, false, 0).await.unwrap();
    assert_eq!(
        share
            .paths
            .load_runtime_status(share_id)
            .unwrap()
            .unwrap()
            .health,
        SyncHealth::Pending
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_peer_does_not_block_the_same_shares_next_peer_exchange() {
    use iroh::{address_lookup::memory::MemoryLookup, endpoint::presets};

    let lookup = MemoryLookup::new();
    let client = Endpoint::builder(presets::Minimal)
        .address_lookup(lookup.clone())
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let slow_server = Endpoint::builder(presets::Minimal)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let fast_server = Endpoint::builder(presets::Minimal)
        .alpns(vec![SYNCBOX_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    lookup.add_endpoint_info(slow_server.addr());
    lookup.add_endpoint_info(fast_server.addr());
    let temporary = TempDir::new().unwrap();
    let client_root = temporary.path().join("client").join("shared");
    let fast_root = temporary.path().join("remote").join("shared");
    fs::create_dir_all(&client_root).unwrap();
    fs::create_dir_all(&fast_root).unwrap();
    fs::write(client_root.join("first.txt"), b"first").unwrap();
    let share_id = ShareId([79; 32]);
    let share = active_share(&client_root, Manifest::empty(share_id, 0), client.id());
    let remote = active_share(&fast_root, Manifest::empty(share_id, 0), fast_server.id());
    let mut peers = KnownPeers::empty();
    peers.add_or_touch(&slow_server.id(), 0);
    peers.add_or_touch(&fast_server.id(), 0);
    share.paths.save_known_peers(share_id, &peers).unwrap();
    let registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(share_id, share)])),
    };
    let remote_registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(share_id, remote)])),
    };
    let fast_handler = spawn_accept_loop(fast_server.clone(), remote_registry);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let receiver = slow_server.clone();
    let slow_handler = tokio::spawn(async move {
        let connection = receiver.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        recv.read_exact(&mut [0; CLIENT_HELLO_LENGTH])
            .await
            .unwrap();
        ready_tx.send(()).unwrap();
        connection.closed().await;
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let notify = Notify::new();
    let runner = run_share_workers(&client, &registry, &notify, async {
        shutdown_rx.await.context("shutdown sender dropped")
    });
    let verify = async {
        timeout(Duration::from_secs(8), async {
            ready_rx.await.unwrap();
            while !fast_root.join("first.txt").is_file() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            fs::write(client_root.join("second.txt"), b"second").unwrap();
            while !fast_root.join("second.txt").is_file() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        shutdown_tx.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(runner, verify);
    result.unwrap();
    assert_eq!(fs::read(fast_root.join("second.txt")).unwrap(), b"second");
    slow_handler.await.unwrap();
    slow_server.close().await;
    fast_server.close().await;
    fast_handler.await.unwrap();
}
