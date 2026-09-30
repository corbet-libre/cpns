//! Trusted server composition: scoped pin storage and spent-token verification.
//!
//! The caller authenticates members, validates schema fields and chooses a
//! community database. Storage and token implementations are trusted code.

mod memory;

#[cfg(feature = "storage")]
pub mod libsql;

use std::{fmt, future::Future};

use crate::Fingerprint;

pub use memory::MemoryStore;

/// The current pin, with an increasing revision used to prevent replay and ABA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The current fingerprint, with no opening information or version tag.
    pub fingerprint: Fingerprint,
    /// Starts at one, never resets, and must fit a positive SQLite INTEGER.
    pub revision: u64,
}

/// A specific transition that a spent change token must authorize in full.
/// This is transient; it is never stored as a change history.
#[derive(Clone, Copy)]
pub struct Change<'a> {
    /// The authenticated community scope selected by the service.
    pub community: &'a str,
    /// The authenticated community member pseudonym.
    pub member: &'a str,
    /// The schema's stable restricted field identifier.
    pub field: &'a str,
    /// Both the digest and the revision that will be replaced.
    pub expected: Pin,
    /// The new device-generated digest.
    pub replacement: Fingerprint,
}

impl Change<'_> {
    /// Validate the transition and compute its next current state.
    pub fn next_pin(&self) -> Result<Pin, Error> {
        validate_key(self.community)?;
        validate_key(self.member)?;
        validate_key(self.field)?;
        if self.expected.revision == 0 || self.expected.revision >= i64::MAX as u64 {
            return Err(Error::InvalidRevision);
        }
        if self.expected.fingerprint == self.replacement {
            return Err(Error::Unchanged);
        }
        Ok(Pin {
            fingerprint: self.replacement,
            revision: self.expected.revision + 1,
        })
    }
}

/// An immutable transition whose spent authorization was verified by [`Pins`].
///
/// Only [`Pins::change`] creates this witness, after `verify_spent` succeeds.
/// Storage adapters can inspect it but cannot construct or alter it. It is
/// consumed by the write; retries go through verification again.
///
/// A plain transition cannot authorize a direct storage write:
///
/// ```compile_fail,E0308
/// use cpns::server::{Change, Store};
/// async fn bypass(store: &impl Store, change: Change<'_>) {
///     store.compare_exchange(change).await.unwrap();
/// }
/// ```
///
/// The witness constructor is private:
///
/// ```compile_fail,E0624
/// use cpns::server::{AuthorizedChange, Change};
/// fn forge(change: Change<'_>) {
///     let _ = AuthorizedChange::new(change);
/// }
/// ```
pub struct AuthorizedChange<'a> {
    change: Change<'a>,
}

impl<'a> AuthorizedChange<'a> {
    fn new(change: Change<'a>) -> Self {
        Self { change }
    }

    /// Inspect exactly the transition authenticated by the spend verifier.
    pub fn change(&self) -> &Change<'a> {
        &self.change
    }
}

/// A coarse error that contains no member, token, field value or driver details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An identifier is empty, contains NUL or exceeds 1024 UTF-8 bytes.
    InvalidIdentifier,
    /// Initial creation would overwrite an existing pin.
    AlreadyPinned,
    /// There is no pin to change.
    NotPinned,
    /// The expected state or community scope does not match current storage.
    Conflict,
    /// The replacement equals the current digest; a fresh salt is required.
    Unchanged,
    /// A revision is invalid or exhausted; it must never wrap or reset.
    InvalidRevision,
    /// No valid, already-spent authorization for this exact transition.
    TokenRejected,
    /// Storage failed, timed out, or returned malformed state. A write outcome
    /// may be uncertain; read current state before retrying the same request.
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentifier => "invalid pin identifier",
            Self::AlreadyPinned => "field is already pinned",
            Self::NotPinned => "field is not pinned",
            Self::Conflict => "pin state conflict",
            Self::Unchanged => "replacement fingerprint is unchanged",
            Self::InvalidRevision => "invalid or exhausted pin revision",
            Self::TokenRejected => "spent change authorization rejected",
            Self::Storage => "pin storage failure; reconcile before retrying",
        })
    }
}

impl std::error::Error for Error {}

/// Deliberately opaque token rejection, including verifier unavailability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenRejected;

/// Adapter contract for cblc; no accepting implementation is supplied.
///
/// Success MUST authenticate an already completed, irreversible spend for the
/// cpns change purpose, bound to EVERY field of `Change`, including old revision
/// and both fingerprints. A token may authorize exactly one such transition,
/// never several fields, members, communities, or revisions. Verification must
/// permit retries of the identical request after an uncertain storage result.
/// Do not merely verify a token signature, available balance, or unspent token.
/// Do not spend during this method: cblc owns spending and durable replay state.
/// Return rejection on any invalid evidence, outage or unbound field.
pub trait ChangeTokenVerifier: Send + Sync {
    /// Evidence type defined by the eventual cblc adapter; never stored by cpns.
    type Token: Sync + ?Sized;

    /// Authenticate the exact already-spent change authorization.
    fn verify_spent(
        &self,
        change: &Change<'_>,
        token: &Self::Token,
    ) -> impl Future<Output = Result<(), TokenRejected>> + Send;
}

/// Trusted atomic storage capability, fixed to one community for its lifetime.
///
/// Implementations store only current state. Insert MUST be insert-only and
/// compare_exchange MUST check both digest and revision atomically. Never delete
/// and reinsert a member/field or reset its revision: that revives old tokens.
/// This low-level capability is for service composition, not an untrusted API.
pub trait Store: Send + Sync {
    /// Stable community key selected by the trusted composition root.
    fn community(&self) -> &str;

    /// Read one current pin by its indexed member/field key.
    fn get(
        &self,
        member: &str,
        field: &str,
    ) -> impl Future<Output = Result<Option<Pin>, Error>> + Send;

    /// Create revision one; existing rows MUST never be overwritten.
    fn insert(
        &self,
        member: &str,
        field: &str,
        fingerprint: Fingerprint,
    ) -> impl Future<Output = Result<Pin, Error>> + Send;

    /// Atomically replace exactly the expected pin with its next revision.
    /// Requires the immutable witness issued only by [`Pins::change`].
    /// Check that its community matches this store before writing.
    fn compare_exchange(
        &self,
        change: AuthorizedChange<'_>,
    ) -> impl Future<Output = Result<Pin, Error>> + Send;
}

/// Pin operations over a fixed community store and a trusted spend verifier.
pub struct Pins<S, V> {
    store: S,
    verifier: V,
}

impl<S: Store, V: ChangeTokenVerifier> Pins<S, V> {
    /// Wire trusted capabilities. Member authentication remains with the caller.
    pub fn new(store: S, verifier: V) -> Self {
        Self { store, verifier }
    }

    /// Read the current pin for a credential or a subsequent change request.
    pub async fn get(&self, member: &str, field: &str) -> Result<Option<Pin>, Error> {
        validate_key(member)?;
        validate_key(field)?;
        self.store.get(member, field).await
    }

    /// Create a field's initial pin without a change token. Never overwrites.
    pub async fn pin(
        &self,
        member: &str,
        field: &str,
        fingerprint: Fingerprint,
    ) -> Result<Pin, Error> {
        validate_key(member)?;
        validate_key(field)?;
        self.store.insert(member, field, fingerprint).await
    }

    /// Verify a spent token, then atomically change exactly the expected state.
    /// A competing write fails with Conflict. No token/value/salt is persisted.
    pub async fn change(
        &self,
        member: &str,
        field: &str,
        expected: Pin,
        replacement: Fingerprint,
        token: &V::Token,
    ) -> Result<Pin, Error> {
        let change = Change {
            community: self.store.community(),
            member,
            field,
            expected,
            replacement,
        };
        change.next_pin()?;
        match self.store.get(member, field).await? {
            None => return Err(Error::NotPinned),
            Some(current) if current != expected => return Err(Error::Conflict),
            Some(_) => {}
        }
        self.verifier
            .verify_spent(&change, token)
            .await
            .map_err(|_| Error::TokenRejected)?;
        self.store
            .compare_exchange(AuthorizedChange::new(change))
            .await
    }
}

pub(crate) fn validate_key(key: &str) -> Result<(), Error> {
    if key.is_empty() || key.len() > 1024 || key.contains('\0') {
        Err(Error::InvalidIdentifier)
    } else {
        Ok(())
    }
}
