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
