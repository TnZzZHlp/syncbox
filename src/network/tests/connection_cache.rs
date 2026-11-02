use super::*;
use crate::network::connection_cache::{ConnectionCache, MAX_CACHED_CONNECTIONS};

#[tokio::test]
async fn maintenance_removes_released_empty_slots() {
    let cache = ConnectionCache::default();
    let peer = SecretKey::from_bytes(&[122; 32]).public();
    let lease = cache.slot(peer).await.unwrap().lease().await;
    cache.maintain().await;
    assert!(cache.get(peer).await.is_some());
    drop(lease);
    cache.maintain().await;
    assert!(cache.get(peer).await.is_none());
}

#[tokio::test]
async fn full_pool_preserves_active_peers_until_a_lease_is_released() {
    let cache = ConnectionCache::default();
    let mut leases = Vec::new();
    for seed in 0..MAX_CACHED_CONNECTIONS {
        let peer = SecretKey::from_bytes(&[u8::try_from(seed).unwrap(); 32]).public();
        leases.push(cache.slot(peer).await.unwrap().lease().await);
    }
    cache.maintain().await;
    let next = SecretKey::from_bytes(&[100; 32]).public();
    assert!(cache.slot(next).await.is_err());
    drop(leases.pop());
    assert!(cache.slot(next).await.is_ok());
    drop(leases);
}
