use super::*;
use crate::server::Change;

async fn database(schema: &str) -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("pins.db").display());
    let db = Db::open(crlt::Config::new(url, "")).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "pins", schema)])
        .await
        .unwrap();
    (dir, db)
}

#[tokio::test]
async fn authorized_transition_cannot_cross_a_database_scope() {
    let (_dir, db) = database(SCHEMA).await;
    let source = LibsqlStore::new(&db, "source").unwrap();
    let destination = LibsqlStore::new(&db, "destination").unwrap();
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
async fn malformed_imported_rows_never_become_pins() {
    // A legacy/imported table without CHECK constraints exercises defensive reads.
    // The real driver and indexed community queries remain in use throughout.
    let schema = "CREATE TABLE cpns_pins (
        community_id TEXT NOT NULL, member_id TEXT NOT NULL, field_id TEXT NOT NULL,
        fingerprint BLOB, revision INTEGER,
        PRIMARY KEY (community_id, member_id, field_id)
    ) WITHOUT ROWID";
    let (_dir, db) = database(schema).await;
    let scope = db.community("community").unwrap();
    let store = LibsqlStore::new(&db, "community").unwrap();
    assert_eq!(store.get("member", "absent").await.unwrap(), None);
    for (index, (digest, revision)) in [
        (Value::Text("invalid".into()), Value::Integer(1)),
        (Value::Blob(vec![0; 31]), Value::Integer(1)),
        (Value::Blob(vec![0; 32]), Value::Integer(0)),
        (Value::Blob(vec![0; 32]), Value::Integer(-1)),
        (Value::Blob(vec![0; 32]), Value::Text("invalid".into())),
    ]
    .into_iter()
    .enumerate()
    {
        let field = format!("field-{index}");
        scope
            .execute(
                "INSERT INTO cpns_pins (member_id, field_id, fingerprint, revision) VALUES (?1, ?2, ?3, ?4)",
                params!["member", field.as_str(), digest, revision],
            )
            .await
            .unwrap();
        assert_eq!(store.get("member", &field).await, Err(Error::Storage));
    }
}

#[tokio::test]
async fn missing_sql_table_refuses_reads_and_writes() {
    let schema = "CREATE TABLE unrelated (community_id TEXT PRIMARY KEY) WITHOUT ROWID";
    let (_dir, db) = database(schema).await;
    let store = LibsqlStore::new(&db, "community").unwrap();
    let fingerprint = Fingerprint::from_bytes([1; 32]);
    assert_eq!(store.get("member", "field").await, Err(Error::Storage));
    assert_eq!(
        store.insert("member", "field", fingerprint).await,
        Err(Error::Storage)
    );
    let change = Change {
        community: "community",
        member: "member",
        field: "field",
        expected: Pin {
            fingerprint,
            revision: 1,
        },
        replacement: Fingerprint::from_bytes([2; 32]),
    };
    assert_eq!(
        store.compare_exchange(AuthorizedChange::new(change)).await,
        Err(Error::Storage)
    );
}

#[tokio::test]
async fn incompatible_import_schema_refuses_insert_without_creating_a_pin() {
    // A required column in an incompatible imported schema must fail the actual INSERT.
    let schema = SCHEMA.replace(
        "revision INTEGER NOT NULL",
        "import_required TEXT NOT NULL, revision INTEGER NOT NULL",
    );
    let (_dir, db) = database(&schema).await;
    let store = LibsqlStore::new(&db, "community").unwrap();
    assert_eq!(store.get("member", "field").await.unwrap(), None);
    assert_eq!(
        store
            .insert("member", "field", Fingerprint::from_bytes([1; 32]))
            .await,
        Err(Error::Storage)
    );
    assert_eq!(store.get("member", "field").await.unwrap(), None);
}
