#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod opening;

pub use opening::{Fingerprint, MIN_SALT_BYTES, Salt, SaltError, check_opening, fingerprint};
