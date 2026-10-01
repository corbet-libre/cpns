use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{Arc, Mutex},
};

use super::{AuthorizedChange, Error, Pin, Store, validate_key};
use crate::Fingerprint;

type Rows = BTreeMap<(String, String), Pin>;

#[cfg(test)]
#[path = "tests/memory.rs"]
mod boundary_tests;

/// In-memory implementation with atomic operations, useful for tests.
/// Clones share state and community scope. Restarting loses all pins: never use
/// this adapter where issued credentials or spent tokens survive a restart.
#[derive(Clone)]
pub struct MemoryStore {
    community: String,
    rows: Arc<Mutex<Rows>>,
}

impl MemoryStore {
    /// Create an empty database for one community.
    pub fn new(community: impl Into<String>) -> Result<Self, Error> {
        let community = community.into();
        validate_key(&community)?;
        Ok(Self {
            community,
            rows: Arc::default(),
        })
    }
}

impl Store for MemoryStore {
    fn community(&self) -> &str {
        &self.community
    }

    async fn get(&self, member: &str, field: &str) -> Result<Option<Pin>, Error> {
        validate_key(member)?;
        validate_key(field)?;
        Ok(self
            .rows
            .lock()
            .map_err(|_| Error::Storage)?
            .get(&(member.into(), field.into()))
            .copied())
    }

    async fn insert(
        &self,
        member: &str,
        field: &str,
        fingerprint: Fingerprint,
    ) -> Result<Pin, Error> {
        validate_key(member)?;
        validate_key(field)?;
        let pin = Pin {
            fingerprint,
            revision: 1,
        };
        let mut rows = self.rows.lock().map_err(|_| Error::Storage)?;
        match rows.entry((member.into(), field.into())) {
            Entry::Occupied(_) => Err(Error::AlreadyPinned),
            Entry::Vacant(entry) => {
                entry.insert(pin);
                Ok(pin)
            }
        }
    }

    async fn compare_exchange(&self, authorized: AuthorizedChange<'_>) -> Result<Pin, Error> {
        let change = authorized.change();
        let next = change.next_pin()?;
        if change.community != self.community {
            return Err(Error::Conflict);
        }
        let mut rows = self.rows.lock().map_err(|_| Error::Storage)?;
        let current = rows
            .get_mut(&(change.member.into(), change.field.into()))
            .ok_or(Error::Conflict)?;
        if *current != change.expected {
            return Err(Error::Conflict);
        }
        *current = next;
        Ok(next)
    }
}
