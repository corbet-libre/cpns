//! The real storage cut only: no member or spent-proof authority is invented.
use super::*;
use std::{cell::Cell, sync::Arc, time::Duration};

async fn database(connections: usize) -> (tempfile::TempDir, LibsqlStore) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crlt::Config::new(
        format!("file://{}", dir.path().join("pins.db").display()),
        "",
    );
    config.max_connections = connections;
    config.timeout = Duration::from_millis(200);
    config.busy_timeout = Duration::from_millis(50);
    let db = Db::open(config).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "pins", SCHEMA)])
        .await
        .unwrap();
    (dir, LibsqlStore::new(&db, "community").unwrap())
}

async fn transition(store: &LibsqlStore) -> Change<'static> {
    let expected = store
        .insert("member", "field", Fingerprint::from_bytes([1; 32]))
        .await
        .unwrap();
    Change {
        community: "community",
        member: "member",
        field: "field",
        expected,
        replacement: Fingerprint::from_bytes([2; 32]),
    }
}

#[tokio::test]
async fn current_read_uses_original_database_and_refusal_rolls_back_exact_cas() {
    let (_dir, store) = database(2).await;
    let change = transition(&store).await;
    let authority = store
        .insert("member", "other", Fingerprint::from_bytes([3; 32]))
        .await
        .unwrap();
    let checked = Cell::new(false);
    let result = store
        .compare_exchange_current(
            AuthorizedChange::new(change),
            || async {
                assert_eq!(store.get("member", "other").await?, Some(authority));
                checked.set(true);
                Err(Error::TokenRejected)
            },
            || panic!("refused authority cannot reach commit"),
        )
        .await;
    assert_eq!(result, Err(Error::TokenRejected));
    assert!(checked.get());
    assert_eq!(
        store.get("member", "field").await.unwrap(),
        Some(change.expected)
    );
    let next = store
        .compare_exchange_current(
            AuthorizedChange::new(change),
            || async {
                assert_eq!(store.get("member", "other").await?, Some(authority));
                Ok(())
            },
            || Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(next, change.next_pin().unwrap());
}

#[tokio::test]
async fn exclusive_deadline_refuses_before_commit_but_late_reply_stays_committed() {
    let (_dir, store) = database(2).await;
    let change = transition(&store).await;
    let clock = Cell::new(9);
    let result = store
        .compare_exchange_current(
            AuthorizedChange::new(change),
            || async {
                clock.set(10);
                Ok(())
            },
            || {
                if clock.get() < 10 {
                    Ok(())
                } else {
                    Err(Error::TokenRejected)
                }
            },
        )
        .await;
    assert_eq!(result, Err(Error::TokenRejected));
    assert_eq!(
        store.get("member", "field").await.unwrap(),
        Some(change.expected)
    );
    let calls = Cell::new(0);
    let result = store
        .compare_exchange_current(
            AuthorizedChange::new(change),
            || async { Ok(()) },
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok(())
                } else {
                    Err(Error::TokenRejected)
                }
            },
        )
        .await;
    assert_eq!(result, Err(Error::Storage));
    assert_eq!(
        store.get("member", "field").await.unwrap(),
        Some(change.next_pin().unwrap())
    );
}

#[tokio::test]
async fn cancelled_current_check_rolls_back_without_consuming_revision() {
    let (_dir, store) = database(2).await;
    let change = transition(&store).await;
    let reached = Arc::new(tokio::sync::Notify::new());
    let signal = reached.clone();
    let writer = store.clone();
    let task = tokio::spawn(async move {
        writer
            .compare_exchange_current(
                AuthorizedChange::new(change),
                || async move {
                    signal.notify_one();
                    std::future::pending::<Result<(), Error>>().await
                },
                || Ok(()),
            )
            .await
    });
    reached.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        store.get("member", "field").await.unwrap(),
        Some(change.expected)
    );
}

#[tokio::test]
async fn one_connection_refuses_read_under_write_lock_at_the_actual_pool_deadline() {
    let (_dir, store) = database(1).await;
    let change = transition(&store).await;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        store.compare_exchange_current(
            AuthorizedChange::new(change),
            || async { store.get("member", "field").await.map(|_| ()) },
            || panic!("exhausted pool must not reach commit"),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result, Err(Error::Storage));
    assert_eq!(
        store.get("member", "field").await.unwrap(),
        Some(change.expected)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_writer_cannot_change_checked_rows_until_pin_commit() {
    let (_dir, store) = database(3).await;
    let change = transition(&store).await;
    let old = store
        .insert("member", "other", Fingerprint::from_bytes([3; 32]))
        .await
        .unwrap();
    let competing = Change {
        field: "other",
        expected: old,
        replacement: Fingerprint::from_bytes([4; 32]),
        ..change
    };
    let competitor = store.clone();
    let next = store
        .compare_exchange_current(
            AuthorizedChange::new(change),
            || async {
                let attempted = tokio::spawn(async move {
                    competitor
                        .compare_exchange(AuthorizedChange::new(competing))
                        .await
                })
                .await
                .unwrap();
                assert_eq!(attempted, Err(Error::Storage));
                assert_eq!(store.get("member", "other").await?, Some(old));
                Ok(())
            },
            || Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(next, change.next_pin().unwrap());
    assert_eq!(
        store
            .compare_exchange(AuthorizedChange::new(competing))
            .await
            .unwrap(),
        competing.next_pin().unwrap()
    );
}
