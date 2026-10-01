use super::*;

#[tokio::test]
async fn exact_statement_plans_use_the_full_primary_key() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("plans.db").display());
    let db = Db::open(crlt::Config::new(url, "")).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "pins", SCHEMA)])
        .await
        .unwrap();
    let scope = db.community("community").unwrap();
    for (sql, args) in [
        (
            GET,
            vec![Value::Text("member".into()), Value::Text("field".into())],
        ),
        (
            UPDATE,
            vec![
                Value::Blob(vec![1; 32]),
                Value::Integer(2),
                Value::Text("member".into()),
                Value::Text("field".into()),
                Value::Blob(vec![0; 32]),
                Value::Integer(1),
            ],
        ),
    ] {
        let plan = scope.explain(sql, args).await.unwrap();
        plan.assert_indexed().unwrap();
        assert!(
            plan.details()
                .iter()
                .any(|d| d.contains("community_id=? AND member_id=? AND field_id=?")),
            "{plan:?}"
        );
    }
    scope
        .explain(INSERT, params!["member", "field", vec![0_u8; 32]])
        .await
        .unwrap()
        .assert_indexed()
        .unwrap();
}
