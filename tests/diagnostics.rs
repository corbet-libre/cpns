//! Diagnostics retain useful error categories and no input data.
use std::error::Error as _;

use cpns::SaltError;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn salt_errors_are_static_and_have_no_sensitive_source() {
    for (error, message) in [
        (SaltError::TooShort, "salt must contain at least 128 bits"),
        (
            SaltError::RandomnessUnavailable,
            "secure randomness unavailable",
        ),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn server_errors_are_static_and_have_no_driver_source() {
    use cpns::server::Error;

    for (error, message) in [
        (Error::InvalidIdentifier, "invalid pin identifier"),
        (Error::AlreadyPinned, "field is already pinned"),
        (Error::NotPinned, "field is not pinned"),
        (Error::Conflict, "pin state conflict"),
        (Error::Unchanged, "replacement fingerprint is unchanged"),
        (Error::InvalidRevision, "invalid or exhausted pin revision"),
        (Error::TokenRejected, "spent change authorization rejected"),
        (
            Error::Storage,
            "pin storage failure; reconcile before retrying",
        ),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}
