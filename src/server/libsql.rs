//! libSQL storage exclusively through the shared crlt database facade.

use crlt::{Community, Db, Value, params};

use super::{AuthorizedChange, Error, Pin, Store, validate_key};
use crate::Fingerprint;

/// Include this DDL in the service's ordered crlt migration history.
/// cpns does not reserve a global migration number or open its own connection.
pub const SCHEMA: &str = "CREATE TABLE cpns_pins (
    community_id TEXT NOT NULL,
    member_id TEXT NOT NULL CHECK (length(member_id) > 0),
    field_id TEXT NOT NULL CHECK (length(field_id) > 0),
    fingerprint BLOB NOT NULL CHECK (typeof(fingerprint) = 'blob' AND length(fingerprint) = 32),
    revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision > 0),
    PRIMARY KEY (community_id, member_id, field_id)
) WITHOUT ROWID";

const GET: &str =
    "SELECT fingerprint, revision FROM cpns_pins WHERE member_id = ?1 AND field_id = ?2";
const INSERT: &str =
    "INSERT INTO cpns_pins (member_id, field_id, fingerprint, revision) VALUES (?1, ?2, ?3, 1)";
const UPDATE: &str = "UPDATE cpns_pins SET fingerprint = ?1, revision = ?2 WHERE member_id = ?3 AND field_id = ?4 AND fingerprint = ?5 AND revision = ?6";

/// A fixed community capability using crlt's pooled libSQL connections.
#[derive(Clone)]
pub struct LibsqlStore {
    scope: Community,
    community: String,
}

impl LibsqlStore {
    /// Use a service-owned, migrated database. Deploy one DB per community;
    /// crlt adds the community predicate to every statement as defense in depth.
    pub fn new(db: &Db, community: impl Into<String>) -> Result<Self, Error> {
        let community = community.into();
        validate_key(&community)?;
        Ok(Self {
            scope: db
                .community(community.clone())
                .map_err(|_| Error::Storage)?,
            community,
        })
    }
}

impl Store for LibsqlStore {
    fn community(&self) -> &str {
        &self.community
    }

    async fn get(&self, member: &str, field: &str) -> Result<Option<Pin>, Error> {
        validate_key(member)?;
        validate_key(field)?;
        let rows = self
            .scope
            .query(GET, params![member, field])
            .await
            .map_err(|_| Error::Storage)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let Value::Blob(bytes) = row.get_value(0).map_err(|_| Error::Storage)? else {
            return Err(Error::Storage);
        };
        let digest = bytes.as_slice().try_into().map_err(|_| Error::Storage)?;
        let revision = row.get_i64(1).map_err(|_| Error::Storage)?;
        if revision <= 0 {
            return Err(Error::Storage);
        }
        Ok(Some(Pin {
            fingerprint: Fingerprint::from_bytes(digest),
            revision: revision as u64,
        }))
    }

    async fn insert(
        &self,
        member: &str,
        field: &str,
        fingerprint: Fingerprint,
    ) -> Result<Pin, Error> {
        validate_key(member)?;
        validate_key(field)?;
        let mut tx = self.scope.tx().await.map_err(|_| Error::Storage)?;
        if !tx
            .query(GET, params![member, field])
            .await
            .map_err(|_| Error::Storage)?
            .is_empty()
        {
            tx.rollback().await.map_err(|_| Error::Storage)?;
            return Err(Error::AlreadyPinned);
        }
        tx.execute(
            INSERT,
            params![member, field, fingerprint.as_bytes().as_slice()],
        )
        .await
        .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
        Ok(Pin {
            fingerprint,
            revision: 1,
        })
    }

    async fn compare_exchange(&self, authorized: AuthorizedChange<'_>) -> Result<Pin, Error> {
        let change = authorized.change();
        let next = change.next_pin()?;
        if change.community != self.community {
            return Err(Error::Conflict);
        }
        let mut tx = self.scope.tx().await.map_err(|_| Error::Storage)?;
        let changed = tx
            .execute(
                UPDATE,
                params![
                    next.fingerprint.as_bytes().as_slice(),
                    next.revision as i64,
                    change.member,
                    change.field,
                    change.expected.fingerprint.as_bytes().as_slice(),
                    change.expected.revision as i64
                ],
            )
            .await
            .map_err(|_| Error::Storage)?;
        if changed != 1 {
            tx.rollback().await.map_err(|_| Error::Storage)?;
            return Err(Error::Conflict);
        }
        tx.commit().await.map_err(|_| Error::Storage)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
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
}
