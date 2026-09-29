# cpns

**Pins: sealed fingerprints of restricted profile fields.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Status: in
development; interfaces may change. The device API seals canonical field bytes
and checks openings on native Rust and `wasm32-unknown-unknown`.

```rust
use cpns::{Salt, fingerprint, check_opening};

# #[cfg(not(target_arch = "wasm32"))] {
let salt = Salt::generate()?;
let sealed = fingerprint(b"canonical field value", &salt);
assert!(check_opening(&sealed, b"canonical field value", &salt));
# }
# Ok::<(), cpns::SaltError>(())
```

Salts belong exclusively to members' devices. Generate a fresh salt for every
pin and change, including changes back to a previous value. On a browser, use
Web Crypto `crypto.getRandomValues` and `Salt::from_bytes`; opening checks need
no JavaScript bindings or random source. Imported salts must contain at least
16 bytes of cryptographic randomness. `Salt::generate` uses 32 OS-random bytes.
Length checks cannot prove entropy or freshness of externally supplied salts.

The exact v1 format and security boundary are in [docs/CONTRACT.md](docs/CONTRACT.md).

## Dependency survey

Surveyed crates.io and upstream GitHub sources on 2026-09-30 before implementation:

| Candidate | Choice and reason |
|---|---|
| [RustCrypto sha2 0.11](https://github.com/RustCrypto/hashes/tree/master/sha2) (MIT/Apache-2.0) | Selected: maintained SHA-256 implementation with native and portable Wasm backends; simple 32-byte protocol and independent reference vectors. |
| [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3) (CC0/Apache-2.0) | Suitable alternative with domain derivation and constant-time digest equality; no second hash algorithm is needed. |
| [subtle 2.6](https://github.com/dalek-cryptography/subtle) (BSD-3-Clause) | Selected for constant-time digest equality instead of a handwritten comparison. |
| [zeroize 1.9](https://github.com/RustCrypto/utils/tree/master/zeroize) (MIT/Apache-2.0) | Selected to clear owned salt buffers on drop, including rejected imports. This does not erase caller copies, hash internals, or process snapshots. |
| [getrandom 0.4](https://github.com/rust-random/getrandom) (MIT/Apache-2.0) | Selected for native OS randomness, with no fallback on failure. Wasm callers supply their platform randomness. |
| [crlt](https://github.com/corbet-foss/crlt) (LGPL-3.0-only WITH linking exception) | Main already exposes scoped libSQL transactions, migrations and query-plan checks. Selected for the upcoming storage adapter, rather than directly depending on libsql or an ORM. |

`corbet-foss/cblc` does not exist; the architectural home
[`corbet-libs/cblc`](https://github.com/corbet-libs/cblc) is still a placeholder
without a spend-verification API. Integration will use a small local trait,
with no dependency on a scaffold and no local cryptographic token protocol.

## Verification

GitHub Actions runs formatting, strict Clippy, real tests and a Wasm target check
on current stable Rust. Do not run Cargo on the workstation. Opening tests cover
independent SHA-256 vectors, invalid salts, wrong openings, framing ambiguity,
binary/Unicode/empty values and freshly salted reversions.
Never publish this crate to a registry.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under [LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt) [WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt). See [LICENSE.md](LICENSE.md).
