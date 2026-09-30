//! The same contract against the real memory and crlt/libSQL adapters.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use common::{SpentLedger, sealed};
use cpns::server::{
    Change, ChangeTokenVerifier, Error, MemoryStore, Pin, Pins, Store, TokenRejected,
};
use std::sync::Arc;

async fn round_trip(store: impl Store + Clone) {
    let ledger = SpentLedger::default();
    let pins = Pins::new(store.clone(), ledger.clone());
    let community = store.community();
    assert_eq!(pins.get("member", "field").await.unwrap(), None);
    let initial = pins.pin("member", "field", sealed(b"first")).await.unwrap();
    assert_eq!(initial.revision, 1);
    for digest in [initial.fingerprint, sealed(b"cannot overwrite")] {
        assert_eq!(
            pins.pin("member", "field", digest).await,
            Err(Error::AlreadyPinned)
        );
    }
    let new = sealed(b"new");
    let change = Change {
        community,
        member: "member",
        field: "field",
        expected: initial,
        replacement: new,
    };
    let token = ledger.spend(&change);
    assert_eq!(
        pins.change("member", "field", initial, new, &[0; 32]).await,
        Err(Error::TokenRejected)
    );
    assert_eq!(pins.get("member", "field").await.unwrap(), Some(initial));
    for wrong_expected in [
        Pin {
            fingerprint: sealed(b"wrong predecessor"),
            ..initial
        },
        Pin {
            revision: 2,
            ..initial
        },
    ] {
        let wrong_token = ledger.spend(&Change {
            expected: wrong_expected,
            ..change
        });
        assert_eq!(
            pins.change("member", "field", initial, new, &wrong_token)
                .await,
            Err(Error::TokenRejected)
        );
    }
    assert_eq!(
        pins.change("missing", "field", initial, new, &token).await,
        Err(Error::NotPinned)
    );
    assert_eq!(
        pins.change("member", "field", initial, sealed(b"tamper"), &token)
            .await,
        Err(Error::TokenRejected)
    );

    for (member, field) in [("other", "field"), ("member", "other")] {
        pins.pin(member, field, initial.fingerprint).await.unwrap();
        assert_eq!(
            pins.change(member, field, initial, new, &token).await,
            Err(Error::TokenRejected)
        );
        assert_eq!(pins.get(member, field).await.unwrap(), Some(initial));
    }

    let updated = pins
        .change("member", "field", initial, new, &token)
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.fingerprint, new);
    assert_eq!(
        pins.change("member", "field", initial, new, &token).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        pins.change("member", "field", updated, new, &token).await,
        Err(Error::Unchanged)
    );

    // Even a noncompliant client that reuses an earlier digest cannot revive
    // its old authorization: revisions prevent the ABA replay.
    let back = Change {
        expected: updated,
        replacement: initial.fingerprint,
        ..change
    };
    let back_token = ledger.spend(&back);
    let reverted = pins
        .change("member", "field", updated, initial.fingerprint, &back_token)
        .await
        .unwrap();
    assert_eq!(reverted.revision, 3);
    assert_eq!(
        pins.change("member", "field", initial, new, &token).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        pins.change("member", "field", reverted, new, &token).await,
        Err(Error::TokenRejected)
    );
    assert_eq!(pins.get("member", "field").await.unwrap(), Some(reverted));

    let wrong_scope = Change {
        community: "wrong community",
        expected: reverted,
        ..change
    };
    let wrong_token = ledger.spend(&wrong_scope);
    assert_eq!(
        pins.change("member", "field", reverted, new, &wrong_token)
            .await,
        Err(Error::TokenRejected)
    );
    assert_eq!(pins.get("member", "field").await.unwrap(), Some(reverted));
    let fresh = sealed(b"first");
    assert_ne!(fresh, initial.fingerprint);
    let final_change = Change {
        expected: reverted,
        replacement: fresh,
        ..change
    };
    let final_token = ledger.spend(&final_change);
    assert_eq!(
        pins.change("member", "field", reverted, fresh, &final_token)
            .await
            .unwrap()
            .revision,
        4
    );
}

async fn invalid_inputs(store: impl Store + Clone) {
    let pins = Pins::new(store.clone(), SpentLedger::default());
    let digest = sealed(b"never log");
    for key in ["", "nul\0here", &"x".repeat(1025)] {
        assert_eq!(
            pins.pin(key, "field", digest).await,
            Err(Error::InvalidIdentifier)
        );
        assert_eq!(
            pins.pin("member", key, digest).await,
            Err(Error::InvalidIdentifier)
        );
        assert_eq!(store.get(key, "field").await, Err(Error::InvalidIdentifier));
        assert_eq!(
            store.insert("member", key, digest).await,
            Err(Error::InvalidIdentifier)
        );
    }
    let member = "m'; DROP TABLE cpns_pins;--🦀";
    let field = "f' OR 1=1 --";
    let initial = pins.pin(member, field, digest).await.unwrap();
    assert_eq!(pins.get(member, field).await.unwrap(), Some(initial));
    assert!(pins.get("m", field).await.unwrap().is_none());
    let max_key = "a".repeat(1024);
    pins.pin(&max_key, "field", digest).await.unwrap();
    for revision in [0, i64::MAX as u64, u64::MAX] {
        let change = Change {
            community: store.community(),
            member,
            field,
            expected: Pin {
                revision,
                fingerprint: digest,
            },
            replacement: sealed(b"new"),
        };
        assert_eq!(change.next_pin(), Err(Error::InvalidRevision));
        assert_eq!(
            pins.change(member, field, change.expected, change.replacement, &[0; 32])
                .await,
            Err(Error::InvalidRevision)
        );
    }
    assert_eq!(pins.get(member, field).await.unwrap(), Some(initial));
}

struct RendezvousVerifier {
    ledger: SpentLedger,
    barrier: Arc<tokio::sync::Barrier>,
}

impl ChangeTokenVerifier for RendezvousVerifier {
    type Token = [u8; 32];

    async fn verify_spent(
        &self,
        change: &Change<'_>,
        token: &Self::Token,
    ) -> Result<(), TokenRejected> {
        self.ledger.verify_spent(change, token).await?;
        self.barrier.wait().await;
        Ok(())
    }
}

async fn racing_changes(left: impl Store, right: impl Store) {
    let initial = left
        .insert("racer", "field", sealed(b"original"))
        .await
        .unwrap();
    let ledger = SpentLedger::default();
    let change = Change {
        community: left.community(),
        member: "racer",
        field: "field",
        expected: initial,
        replacement: sealed(b"new"),
    };
    let token = ledger.spend(&change);
    let replacement = change.replacement;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let a = Pins::new(
        left,
        RendezvousVerifier {
            ledger: ledger.clone(),
            barrier: barrier.clone(),
        },
    );
    let b = Pins::new(right, RendezvousVerifier { ledger, barrier });
    let (a_result, b_result) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        tokio::join!(
            a.change("racer", "field", initial, replacement, &token),
            b.change("racer", "field", initial, replacement, &token)
        )
    })
    .await
    .unwrap();
    assert_eq!(
        usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()),
        1
    );
    assert_eq!(a_result.err().or(b_result.err()), Some(Error::Conflict));
    assert_eq!(a.get("racer", "field").await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn memory_round_trip() {
    round_trip(MemoryStore::new("community").unwrap()).await;
}

#[tokio::test]
async fn memory_rejects_invalid_inputs() {
    invalid_inputs(MemoryStore::new("community").unwrap()).await;
    assert!(MemoryStore::new("").is_err());
}

#[tokio::test]
async fn memory_serializes_competing_changes() {
    let store = MemoryStore::new("community").unwrap();
    racing_changes(store.clone(), store).await;
}

async fn cancelled_verification(store: impl Store + Clone + 'static) {
    struct WaitingVerifier(Arc<tokio::sync::Notify>);
    impl ChangeTokenVerifier for WaitingVerifier {
        type Token = ();
        async fn verify_spent(&self, _: &Change<'_>, _: &()) -> Result<(), TokenRejected> {
            self.0.notify_one();
            std::future::pending().await
        }
    }
    let initial = store
        .insert("member", "cancelled", sealed(b"initial"))
        .await
        .unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let pins = Pins::new(store.clone(), WaitingVerifier(started.clone()));
    let task = tokio::spawn(async move {
        pins.change("member", "cancelled", initial, sealed(b"unverified"), &())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        store.get("member", "cancelled").await.unwrap(),
        Some(initial)
    );
}

#[tokio::test]
async fn memory_cancellation_before_verification_keeps_current_pin() {
    cancelled_verification(MemoryStore::new("community").unwrap()).await;
}

#[tokio::test]
async fn verifier_failure_cannot_change_a_pin() {
    struct Unavailable;
    impl ChangeTokenVerifier for Unavailable {
        type Token = ();
        async fn verify_spent(&self, _: &Change<'_>, _: &()) -> Result<(), TokenRejected> {
            Err(TokenRejected)
        }
    }
    let store = MemoryStore::new("community").unwrap();
    let pins = Pins::new(store, Unavailable);
    let initial = pins
        .pin("member", "field", sealed(b"original"))
        .await
        .unwrap();
    assert_eq!(
        pins.change("member", "field", initial, sealed(b"new"), &())
            .await,
        Err(Error::TokenRejected)
    );
    assert_eq!(pins.get("member", "field").await.unwrap(), Some(initial));
}

#[cfg(feature = "storage")]
mod database {
    use super::*;
    use cpns::Fingerprint;
    use cpns::server::libsql::{LibsqlStore, SCHEMA};
    use crlt::{Config, Db, Migration, Value, params};

    async fn open(url: String) -> Db {
        let db = Db::open(Config::new(url, "")).await.unwrap();
        db.migrate(&[Migration::new(1, "pins", SCHEMA)])
            .await
            .unwrap();
        db
    }

    async fn fixture() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = open(format!("file://{}", dir.path().join("pins.db").display())).await;
        (dir, db)
    }

    #[tokio::test]
    async fn libsql_round_trip() {
        let (_dir, db) = fixture().await;
        round_trip(LibsqlStore::new(&db, "community").unwrap()).await;
    }

    #[tokio::test]
    async fn libsql_rejects_invalid_inputs() {
        let (_dir, db) = fixture().await;
        invalid_inputs(LibsqlStore::new(&db, "community").unwrap()).await;
        assert!(LibsqlStore::new(&db, "").is_err());
    }

    #[tokio::test]
    async fn libsql_cancellation_before_verification_keeps_current_pin() {
        let (_dir, db) = fixture().await;
        cancelled_verification(LibsqlStore::new(&db, "community").unwrap()).await;
    }

    #[tokio::test]
    async fn retry_after_storage_timeout_reuses_the_same_spent_authorization() {
        struct HoldLease {
            scope: crlt::Community,
            ledger: SpentLedger,
            held: Arc<tokio::sync::Mutex<Option<crlt::Transaction>>>,
        }
        impl ChangeTokenVerifier for HoldLease {
            type Token = [u8; 32];
            async fn verify_spent(
                &self,
                change: &Change<'_>,
                token: &Self::Token,
            ) -> Result<(), TokenRejected> {
                self.ledger.verify_spent(change, token).await?;
                *self.held.lock().await = Some(self.scope.tx().await.unwrap());
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::new(
            format!("file://{}", dir.path().join("timeout.db").display()),
            "",
        );
        config.timeout = std::time::Duration::from_millis(500);
        config.busy_timeout = std::time::Duration::from_millis(50);
        let db = Db::open(config).await.unwrap();
        db.migrate(&[Migration::new(1, "pins", SCHEMA)])
            .await
            .unwrap();
        let store = LibsqlStore::new(&db, "community").unwrap();
        let initial = store
            .insert("member", "field", sealed(b"initial"))
            .await
            .unwrap();
        let change = Change {
            community: "community",
            member: "member",
            field: "field",
            expected: initial,
            replacement: sealed(b"new"),
        };
        let ledger = SpentLedger::default();
        let token = ledger.spend(&change);
        let held = Arc::new(tokio::sync::Mutex::new(None));
        let pins = Pins::new(
            store.clone(),
            HoldLease {
                scope: db.community("community").unwrap(),
                ledger: ledger.clone(),
                held: held.clone(),
            },
        );
        assert_eq!(
            pins.change("member", "field", initial, change.replacement, &token)
                .await,
            Err(Error::Storage)
        );
        let transaction = held.lock().await.take().unwrap();
        transaction.rollback().await.unwrap();
        assert_eq!(store.get("member", "field").await.unwrap(), Some(initial));
        let pins = Pins::new(store, ledger);
        assert_eq!(
            pins.change("member", "field", initial, change.replacement, &token)
                .await
                .unwrap()
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn separate_database_handles_serialize_competing_changes() {
        let (dir, left) = fixture().await;
        let right = open(format!("file://{}", dir.path().join("pins.db").display())).await;
        racing_changes(
            LibsqlStore::new(&left, "community").unwrap(),
            LibsqlStore::new(&right, "community").unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn communities_are_isolated_even_in_one_database() {
        let (_dir, db) = fixture().await;
        let ledger = SpentLedger::default();
        let a = Pins::new(LibsqlStore::new(&db, "a").unwrap(), ledger.clone());
        let b = Pins::new(
            LibsqlStore::new(&db, "b' OR 1=1 --").unwrap(),
            ledger.clone(),
        );
        let first = sealed(b"initial");
        let original = a.pin("member", "field", first).await.unwrap();
        assert_eq!(b.get("member", "field").await.unwrap(), None);
        b.pin("member", "field", first).await.unwrap();
        let change = Change {
            community: "a",
            member: "member",
            field: "field",
            expected: original,
            replacement: sealed(b"new"),
        };
        let token = ledger.spend(&change);
        assert_eq!(
            b.change("member", "field", original, change.replacement, &token)
                .await,
            Err(Error::TokenRejected)
        );
        a.change("member", "field", original, change.replacement, &token)
            .await
            .unwrap();
        assert_eq!(b.get("member", "field").await.unwrap(), Some(original));
    }

    #[tokio::test]
    async fn reopen_preserves_pins_revisions_and_replay_protection() {
        let (dir, db) = fixture().await;
        let ledger = SpentLedger::default();
        let pins = Pins::new(LibsqlStore::new(&db, "community").unwrap(), ledger.clone());
        let initial = pins.pin("member", "field", sealed(b"first")).await.unwrap();
        let change = Change {
            community: "community",
            member: "member",
            field: "field",
            expected: initial,
            replacement: sealed(b"next"),
        };
        let token = ledger.spend(&change);
        let next = pins
            .change("member", "field", initial, change.replacement, &token)
            .await
            .unwrap();
        drop(pins);
        drop(db);
        let db = open(format!("file://{}", dir.path().join("pins.db").display())).await;
        assert_eq!(
            db.migrate(&[Migration::new(1, "pins", SCHEMA)])
                .await
                .unwrap(),
            0
        );
        let pins = Pins::new(LibsqlStore::new(&db, "community").unwrap(), ledger);
        assert_eq!(pins.get("member", "field").await.unwrap(), Some(next));
        assert_eq!(
            pins.change("member", "field", initial, change.replacement, &token)
                .await,
            Err(Error::Conflict)
        );
        let rows = db
            .community("community")
            .unwrap()
            .query(
                "SELECT * FROM cpns_pins WHERE member_id = ?1 AND field_id = ?2",
                params!["member", "field"],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].columns(),
            [
                "community_id",
                "member_id",
                "field_id",
                "fingerprint",
                "revision"
            ]
        );
    }

    #[tokio::test]
    async fn schema_rejects_corruption_and_overflow_without_losing_state() {
        let (_dir, db) = fixture().await;
        let store = LibsqlStore::new(&db, "community").unwrap();
        let initial = store
            .insert("member", "field", sealed(b"first"))
            .await
            .unwrap();
        let scope = db.community("community").unwrap();
        for value in [
            Value::Blob(vec![0; 31]),
            Value::Blob(vec![0; 33]),
            Value::Text("x".repeat(32)),
            Value::Null,
        ] {
            assert!(scope.execute("UPDATE cpns_pins SET fingerprint = ?1 WHERE member_id = ?2 AND field_id = ?3", params![value, "member", "field"]).await.is_err());
        }
        for revision in [
            Value::Integer(0),
            Value::Integer(-1),
            Value::Real(1.5),
            Value::Null,
        ] {
            assert!(
                scope
                    .execute(
                        "UPDATE cpns_pins SET revision = ?1 WHERE member_id = ?2 AND field_id = ?3",
                        params![revision, "member", "field"]
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(store.get("member", "field").await.unwrap(), Some(initial));
        scope
            .execute(
                "UPDATE cpns_pins SET revision = ?1 WHERE member_id = ?2 AND field_id = ?3",
                params![i64::MAX, "member", "field"],
            )
            .await
            .unwrap();
        let exhausted = store.get("member", "field").await.unwrap().unwrap();
        let change = Change {
            community: "community",
            member: "member",
            field: "field",
            expected: exhausted,
            replacement: sealed(b"new"),
        };
        assert_eq!(
            Pins::new(store, SpentLedger::default())
                .change("member", "field", exhausted, change.replacement, &[0; 32])
                .await,
            Err(Error::InvalidRevision)
        );
    }

    #[tokio::test]
    async fn missing_migration_returns_only_a_redacted_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(Config::new(
            format!("file://{}", dir.path().join("empty.db").display()),
            "",
        ))
        .await
        .unwrap();
        let store = LibsqlStore::new(&db, "private-community").unwrap();
        let error = store
            .insert(
                "private-member",
                "private-field",
                Fingerprint::from_bytes([7; 32]),
            )
            .await
            .unwrap_err();
        assert_eq!(error, Error::Storage);
        assert_eq!(format!("{error:?}"), "Storage");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[tokio::test]
    async fn optional_real_turso_round_trip() {
        let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN"))
        else {
            eprintln!("skipped: TURSO_URL and TURSO_TOKEN are both required");
            return;
        };
        if url.is_empty() || token.is_empty() {
            eprintln!("skipped: TURSO_URL and TURSO_TOKEN must both be nonempty");
            return;
        }
        let db = Db::open(Config::new(url, token)).await.unwrap();
        db.migrate(&[Migration::new(1, "pins", SCHEMA)])
            .await
            .unwrap();
        let nonce = SaltForTest::new();
        let community = format!("cpns-test-{}", nonce.0);
        round_trip(LibsqlStore::new(&db, &community).unwrap()).await;
        // This environment opt-in is only for a disposable database. Delete the
        // synthetic community's rows to leave no test member state behind.
        db.community(community)
            .unwrap()
            .execute("DELETE FROM cpns_pins", ())
            .await
            .unwrap();
    }

    struct SaltForTest(String);
    impl SaltForTest {
        fn new() -> Self {
            Self(
                cpns::Salt::generate()
                    .unwrap()
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            )
        }
    }
}
