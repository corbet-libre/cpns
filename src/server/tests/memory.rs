use super::*;
use crate::server::Change;

#[tokio::test]
async fn authorized_transition_cannot_cross_a_store_scope() {
    let source = MemoryStore::new("source").unwrap();
    let destination = MemoryStore::new("destination").unwrap();
    let original = Fingerprint::from_bytes([1; 32]);
    let expected = source.insert("member", "field", original).await.unwrap();
    destination
        .insert("member", "field", original)
        .await
        .unwrap();
    let transition = Change {
        community: "source",
        member: "member",
        field: "field",
        expected,
        replacement: Fingerprint::from_bytes([2; 32]),
    };
    let result = destination
        .compare_exchange(AuthorizedChange::new(transition))
        .await;
    assert_eq!(result, Err(Error::Conflict));
    assert_eq!(
        destination.get("member", "field").await.unwrap(),
        Some(expected)
    );
    assert_eq!(source.get("member", "field").await.unwrap(), Some(expected));
}

#[tokio::test]
async fn stale_or_missing_rows_refuse_an_authorized_compare_exchange() {
    let store = MemoryStore::new("community").unwrap();
    let original = Fingerprint::from_bytes([1; 32]);
    let expected = store.insert("member", "field", original).await.unwrap();
    let transition = Change {
        community: "community",
        member: "member",
        field: "field",
        expected,
        replacement: Fingerprint::from_bytes([2; 32]),
    };
    let next = store
        .compare_exchange(AuthorizedChange::new(transition))
        .await
        .unwrap();
    assert_eq!(
        store
            .compare_exchange(AuthorizedChange::new(transition))
            .await,
        Err(Error::Conflict)
    );
    let missing = Change {
        field: "absent",
        ..transition
    };
    assert_eq!(
        store.compare_exchange(AuthorizedChange::new(missing)).await,
        Err(Error::Conflict)
    );
    assert_eq!(store.get("member", "field").await.unwrap(), Some(next));
    assert_eq!(store.get("member", "absent").await.unwrap(), None);
}

#[tokio::test]
async fn poisoned_store_refuses_every_operation() {
    let store = MemoryStore::new("community").unwrap();
    let expected = store
        .insert("member", "field", Fingerprint::from_bytes([1; 32]))
        .await
        .unwrap();
    let peer = store.clone();
    let interrupted = std::thread::spawn(move || {
        let _guard = peer.rows.lock().unwrap();
        panic!("interrupt a held storage lock");
    })
    .join();
    assert!(interrupted.is_err());
    assert_eq!(store.get("member", "field").await, Err(Error::Storage));
    assert_eq!(
        store.insert("member", "new", expected.fingerprint).await,
        Err(Error::Storage)
    );
    let change = Change {
        community: "community",
        member: "member",
        field: "field",
        expected,
        replacement: Fingerprint::from_bytes([2; 32]),
    };
    assert_eq!(
        store.compare_exchange(AuthorizedChange::new(change)).await,
        Err(Error::Storage)
    );
}
