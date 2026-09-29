use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Smallest accepted salt: 128 bits. Length alone cannot establish entropy.
pub const MIN_SALT_BYTES: usize = 16;
const DOMAIN: &[u8] = b"cpns:pin:sha256:v1\0";

/// A device-owned opening secret, zeroized on drop and redacted in Debug.
///
/// Generate a fresh, independent salt for every initial pin and every change.
/// Never send this value to the permanent server. Back it up only on devices.
pub struct Salt(Zeroizing<Vec<u8>>);

/// Salt validation or operating-system randomness failure, without input data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaltError {
    /// The supplied salt has fewer than 16 bytes.
    TooShort,
    /// The operating system could not supply secure randomness.
    RandomnessUnavailable,
}

impl fmt::Display for SaltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "salt must contain at least 128 bits",
            Self::RandomnessUnavailable => "secure randomness unavailable",
        })
    }
}

impl std::error::Error for SaltError {}

impl Salt {
    /// Import a device opening. The caller guarantees cryptographic randomness
    /// and freshness; on browsers use Web Crypto `crypto.getRandomValues`.
    /// Rejecting a short input also zeroizes the owned buffer.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SaltError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < MIN_SALT_BYTES {
            return Err(SaltError::TooShort);
        }
        Ok(Self(bytes))
    }

    /// Generate a fresh 256-bit salt using the native OS random source.
    /// Errors fail closed; there is no deterministic fallback.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate() -> Result<Self, SaltError> {
        let mut bytes = Zeroizing::new(vec![0; 32]);
        getrandom::fill(&mut bytes).map_err(|_| SaltError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Borrow secret bytes for device storage or peer-to-peer opening.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salt([REDACTED])")
    }
}

/// A v1 SHA-256 fingerprint. Exactly 32 bytes on the wire.
///
/// Comparison uses `subtle`; Debug deliberately omits the identifying digest.
/// Importing bytes does not authenticate their origin: check the signed
/// community credential before trusting a fingerprint supplied by a peer.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Import an already computed v1 digest; no value or salt is needed.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The v1 digest bytes, suitable for a signed credential or database blob.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Fingerprint {}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprint([REDACTED])")
    }
}

/// Seal canonical field bytes on a device, with a fresh independent salt.
///
/// SHA-256(domain || u64be(value length) || value || u64be(salt length) || salt).
/// Framing prevents ambiguous concatenations. No Unicode/JSON normalization is
/// implicit; the schema/client must agree on the exact bytes before sealing.
pub fn fingerprint(value: &[u8], salt: &Salt) -> Fingerprint {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
    hash.update((salt.as_bytes().len() as u64).to_be_bytes());
    hash.update(salt.as_bytes());
    Fingerprint(hash.finalize().into())
}

/// Check an opening locally, without storage, networking, or randomness.
/// Digest comparison is constant-time; hashing cost depends on input length.
pub fn check_opening(expected: &Fingerprint, value: &[u8], salt: &Salt) -> bool {
    fingerprint(value, salt) == *expected
}
