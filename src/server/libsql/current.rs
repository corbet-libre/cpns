//! Current owner authority is checked while the original CAS holds its write lock.
use super::*;
use crate::server::{Change, ChangeTokenVerifier, Pins};
use std::future::Future;

impl<V: ChangeTokenVerifier> Pins<LibsqlStore, V> {
    /// Consume an exact verified spend with current application authority.
    /// `current` must perform genuine read-only owner checks against this same
    /// database while the caller retains its member lease. It must not start a
    /// nested writer. A separate pooled read needs another connection; an
    /// exhausted/single-connection pool refuses at CRLT's configured deadline.
    /// `cut` checks the shared monotonic clock and exclusive authority deadline
    /// immediately before commit and after its return. An error after commit is
    /// reported as `Error::Storage`: reconcile the existing pin, never assume
    /// rollback or re-spend. These samples do not guarantee physical commit
    /// latency or that storage completes before the authority deadline.
    pub async fn change_current<F, Fut, C>(
        &self,
        change: Change<'_>,
        token: &V::Token,
        current: F,
        cut: C,
    ) -> Result<Pin, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), Error>>,
        C: Fn() -> Result<(), Error>,
    {
        let authorized = self.authorize(change, token).await?;
        self.store
            .compare_exchange_current(authorized, current, cut)
            .await
    }
}

#[cfg(test)]
#[path = "../tests/current.rs"]
mod tests;
