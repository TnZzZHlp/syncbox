use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn busy_receiver_waits_for_stream_capacity_instead_of_resetting_the_stream() {
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
    let client_root = temporary.path().join("client").join("shared");
    let server_root = temporary.path().join("server").join("shared");
    fs::create_dir_all(&client_root).unwrap();
    fs::create_dir_all(&server_root).unwrap();
    let share_id = ShareId([71; 32]);
    let share = active_share(&client_root, Manifest::empty(share_id, 0), client.id());
    let registry = ShareRegistry {
        shares: Arc::new(HashMap::from([(
            share_id,
            active_share(&server_root, Manifest::empty(share_id, 0), server.id()),
        )])),
    };
    let receiver = server.clone();
    let handler = tokio::spawn(async move {
        let connection = receiver.accept().await.unwrap().await.unwrap();
        handle_incoming(connection, registry, Arc::new(Semaphore::new(1)))
            .await
            .unwrap();
    });
    timeout(Duration::from_secs(3), async {
        let (send, recv, lease) = share
            .connections
            .open_stream(&client, server.id())
            .await
            .unwrap();
        let mut send = ProgressIo::new(send, IO_IDLE_TIMEOUT);
        let mut recv = ProgressIo::new(recv, IO_IDLE_TIMEOUT);
        let hello = make_client_hello(
            &share.config().unwrap(),
            &client.id(),
            &server.id(),
            [72; 32],
        );
        send.write_all(&hello).await.unwrap();
        read_server_hello(&mut recv).await.unwrap();
        let (result, ()) = tokio::join!(sync_with_peer(&client, &share, server.id()), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop((send, recv, lease));
        },);
        result.unwrap();
    })
    .await
    .unwrap();
    client.close().await;
    handler.await.unwrap();
    server.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn synchronization_reuses_one_connection_across_shares_and_rounds() {
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
    let connections = Arc::new(ConnectionPool::default());
    let mut clients = Vec::new();
    let mut shares = HashMap::new();
    for seed in [61, 62] {
        let share_id = ShareId([seed; 32]);
        let client_root = temporary.path().join("client").join(seed.to_string());
        let server_root = temporary.path().join("server").join(seed.to_string());
        fs::create_dir_all(&client_root).unwrap();
        fs::create_dir_all(&server_root).unwrap();
        let mut share = active_share(&client_root, Manifest::empty(share_id, 0), client.id());
        Arc::get_mut(&mut share).unwrap().connections = Arc::clone(&connections);
        clients.push(share);
        shares.insert(
            share_id,
            active_share(&server_root, Manifest::empty(share_id, 0), server.id()),
        );
    }
    let registry = ShareRegistry {
        shares: Arc::new(shares),
    };
    let receiver = server.clone();
    let handler = tokio::spawn(async move {
        let connection = receiver.accept().await.unwrap().await.unwrap();
        handle_incoming(
            connection,
            registry,
            Arc::new(Semaphore::new(MAX_INCOMING_HANDLERS)),
        )
        .await
        .unwrap();
    });
    timeout(Duration::from_secs(10), async {
        let (send, recv, stalled_lease) =
            connections.open_stream(&client, server.id()).await.unwrap();
        let mut stalled_send = ProgressIo::new(send, IO_IDLE_TIMEOUT);
        let mut stalled_recv = ProgressIo::new(recv, IO_IDLE_TIMEOUT);
        let hello = make_client_hello(
            &clients[0].config().unwrap(),
            &client.id(),
            &server.id(),
            [66; 32],
        );
        stalled_send.write_all(&hello).await.unwrap();
        read_server_hello(&mut stalled_recv).await.unwrap();
        sync_with_peer(&client, &clients[1], server.id())
            .await
            .unwrap();
        drop((stalled_send, stalled_recv, stalled_lease));
        for _ in 0..2 {
            for share in &clients {
                sync_with_peer(&client, share, server.id()).await.unwrap();
            }
        }
    })
    .await
    .unwrap();
    client.close().await;
    handler.await.unwrap();
    server.close().await;
}
