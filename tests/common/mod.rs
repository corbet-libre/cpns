use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use cpns::{
    Fingerprint, Salt, fingerprint,
    server::{Change, ChangeTokenVerifier, Pin, TokenRejected},
};

#[derive(Clone, Default)]
pub struct SpentLedger(Arc<Mutex<HashMap<[u8; 32], Authorization>>>);

struct Authorization {
    community: String,
    member: String,
    field: String,
    expected: Pin,
    replacement: Fingerprint,
}

impl SpentLedger {
    // Test-only authority for the external cblc seam. No cpns logic is mocked:
    // receipts are recorded and retrieved, and every operation field is checked.
    pub fn spend(&self, change: &Change<'_>) -> [u8; 32] {
        let token = Salt::generate().unwrap().as_bytes().try_into().unwrap();
        self.0.lock().unwrap().insert(
            token,
            Authorization {
                community: change.community.into(),
                member: change.member.into(),
                field: change.field.into(),
                expected: change.expected,
                replacement: change.replacement,
            },
        );
        token
    }
}

impl ChangeTokenVerifier for SpentLedger {
    type Token = [u8; 32];

    async fn verify_spent(
        &self,
        change: &Change<'_>,
        token: &Self::Token,
    ) -> Result<(), TokenRejected> {
        let ledger = self.0.lock().unwrap();
        let authorization = ledger.get(token).ok_or(TokenRejected)?;
        if authorization.community != change.community
            || authorization.member != change.member
            || authorization.field != change.field
            || authorization.expected != change.expected
            || authorization.replacement != change.replacement
        {
            return Err(TokenRejected);
        }
        Ok(())
    }
}

pub fn sealed(value: &[u8]) -> Fingerprint {
    fingerprint(value, &Salt::generate().unwrap())
}
