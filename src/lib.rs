#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod opening;

pub use opening::{
    Fingerprint, FingerprintContext, MIN_SALT_BYTES, Salt, SaltError, check_opening,
    check_opening_v2, fingerprint, fingerprint_v2,
};

#[cfg(not(target_arch = "wasm32"))]
pub mod server;
