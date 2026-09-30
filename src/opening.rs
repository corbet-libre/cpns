use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Smallest accepted salt: 128 bits. Length alone cannot establish entropy.
pub const MIN_SALT_BYTES: usize = 16;
const DOMAIN: &[u8] = b"cpns:pin:sha256:v1\0";
const DOMAIN_V2: &[u8] = b"cpns:pin:sha256:v2\0";

/// A device-owned opening secret, zeroized on drop and redacted in Debug.
///
/// Generate a fresh, independent salt for every initial pin and every change.
/// Never send this value to the permanent server. Back it up only on devices.
pub struct Salt(Zeroizing<Vec<u8>>);

/// Salt validation or platform randomness failure, without input data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaltError {
    /// The supplied salt has fewer than 16 bytes.
    TooShort,
    /// The platform could not supply secure randomness.
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

    /// Generate a fresh 256-bit salt using the platform's secure random source.
    /// On `wasm32-unknown-unknown`, enable `wasm` for getrandom's `wasm_js`
    /// backend (Web Crypto in browsers and supported JavaScript runtimes).
    /// Errors fail closed; there is no deterministic fallback.
    #[cfg(any(not(target_arch = "wasm32"), feature = "wasm"))]
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

/// A SHA-256 fingerprint. Exactly 32 bytes on the wire, without a version tag.
///
/// Comparison uses `subtle`; Debug deliberately omits the identifying digest.
/// Importing bytes does not authenticate their origin: check the signed
/// community credential before trusting a fingerprint supplied by a peer.
/// The caller's authenticated protocol selects v1 (default) or opt-in v2;
/// never infer the version from bytes or fall back after a failed opening.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Import an already computed digest; no value or salt is needed.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Digest bytes, suitable for a signed credential or database blob.
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

/// Seal canonical field bytes using default v1, with a fresh independent salt.
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

/// The exact UTF-8 identifiers bound into an opt-in v2 fingerprint.
///
/// Obtain these from authenticated community/member/schema context. No
/// normalization or identifier validation occurs here. Salt freshness and
/// secrecy remain required even when different contexts are used.
#[derive(Clone, Copy)]
pub struct FingerprintContext<'a> {
    /// The community identifier from the authenticated credential context.
    pub community: &'a str,
    /// The community member's canonical pseudonym representation.
    pub member: &'a str,
    /// The schema's stable restricted field identifier.
    pub field: &'a str,
}

/// Opt into v2: bind a pin to its community, member and field as well as opening.
///
/// SHA-256(v2 domain || framed community || framed member || framed field ||
/// framed value || framed salt), where each frame is u64be(byte length) || bytes.
/// This does not change [`fingerprint`], which remains v1. The owning protocol
/// must authenticate the chosen version; a digest alone carries no version tag.
pub fn fingerprint_v2(context: &FingerprintContext<'_>, value: &[u8], salt: &Salt) -> Fingerprint {
    let mut hash = Sha256::new();
    hash.update(DOMAIN_V2);
    for bytes in [
        context.community.as_bytes(),
        context.member.as_bytes(),
        context.field.as_bytes(),
        value,
        salt.as_bytes(),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Fingerprint(hash.finalize().into())
}

/// Check an opt-in v2 opening and its authenticated context, with no v1 fallback.
/// Like [`check_opening`], this uses constant-time digest comparison and no I/O.
pub fn check_opening_v2(
    expected: &Fingerprint,
    context: &FingerprintContext<'_>,
    value: &[u8],
    salt: &Salt,
) -> bool {
    fingerprint_v2(context, value, salt) == *expected
}
