# cpns

**Pins: sealed fingerprints of restricted profile fields.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Status: in
development; interfaces may change. The device API seals canonical field bytes
and checks openings on native Rust and `wasm32-unknown-unknown`.

```rust
use cpns::{Salt, fingerprint, check_opening};

# #[cfg(any(not(target_arch = "wasm32"), feature = "wasm"))] {
let salt = Salt::generate()?;
let sealed = fingerprint(b"canonical field value", &salt);
assert!(check_opening(&sealed, b"canonical field value", &salt));
# }
# Ok::<(), cpns::SaltError>(())
```

Salts belong exclusively to members' devices. Generate a fresh salt for every
pin and change, including changes back to a previous value. Enable the opt-in
`wasm` feature on `wasm32-unknown-unknown` to use `Salt::generate` through
getrandom's `wasm_js` backend (Web Crypto `crypto.getRandomValues`). Without it,
import platform randomness with `Salt::from_bytes`; opening checks need no
JavaScript bindings or random source. Imported salts must contain at least
16 bytes of cryptographic randomness. `Salt::generate` uses 32 secure random bytes.
Length checks cannot prove entropy or freshness of externally supplied salts.

The exact formats and security boundary are in [docs/CONTRACT.md](docs/CONTRACT.md).
`fingerprint` and `check_opening` keep v1 as the default. To bind the digest itself
to community, member pseudonym and field, explicitly opt into `fingerprint_v2`
and `check_opening_v2` with a `FingerprintContext`:

```rust
use cpns::{FingerprintContext, Salt, fingerprint_v2, check_opening_v2};

# #[cfg(any(not(target_arch = "wasm32"), feature = "wasm"))] {
let context = FingerprintContext {
    community: "community",
    member: "member-pseudonym",
    field: "restricted-field",
};
let salt = Salt::generate()?;
let sealed = fingerprint_v2(&context, b"canonical field value", &salt);
assert!(check_opening_v2(&sealed, &context, b"canonical field value", &salt));
# }
# Ok::<(), cpns::SaltError>(())
```

Both versions use RustCrypto SHA-256 and the same 32-byte `Fingerprint` type.
The owning signed protocol must select the version explicitly; never guess it
or retry a failed v2 opening as v1. No stored v1 pin is automatically converted.
Re-pinning with v2 requires a fresh salt and the usual spent change token.

## Dependency survey

Surveyed crates.io and upstream GitHub sources on 2026-09-30 before implementation:

| Candidate | Choice and reason |
|---|---|
| [RustCrypto sha2 0.11](https://github.com/RustCrypto/hashes/tree/master/sha2) (MIT/Apache-2.0) | Selected: maintained SHA-256 implementation with native and portable Wasm backends; simple 32-byte protocol and independent reference vectors. |
| [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3) (CC0/Apache-2.0) | Suitable alternative with domain derivation and constant-time digest equality; no second hash algorithm is needed. |
| [subtle 2.6](https://github.com/dalek-cryptography/subtle) (BSD-3-Clause) | Selected for constant-time digest equality instead of a handwritten comparison. |
| [zeroize 1.9](https://github.com/RustCrypto/utils/tree/master/zeroize) (MIT/Apache-2.0) | Selected to clear owned salt buffers on drop, including rejected imports. This does not erase caller copies, hash internals, or process snapshots. |
| [getrandom 0.4](https://github.com/rust-random/getrandom) (MIT/Apache-2.0) | Selected for native OS randomness and opt-in `wasm_js` Web Crypto support, with no fallback on failure or handwritten JavaScript randomness adapter. |
| [wasm-bindgen-test 0.3](https://github.com/wasm-bindgen/wasm-bindgen/tree/main/crates/test) (MIT/Apache-2.0) | Selected as a Wasm-only dev dependency to execute the same opening tests in a browser. Upstream's matching prebuilt runner avoids compiling a separate test tool in CI; wasm-pack is an alternative orchestrator, unnecessary for this single test target. |
| [crlt](https://github.com/corbet-foss/crlt) (LGPL-3.0-only WITH linking exception) | Main exposes scoped libSQL transactions, migrations and query-plan checks. Selected for the storage adapter, rather than directly depending on libsql or an ORM. |

The native default `storage` feature follows `crlt` main, with its resolved
revision recorded in Cargo.lock. It delegates to
the official `libsql` client; cpns has no direct database-driver dependency.
Use `--no-default-features` for device-only consumers; Wasm excludes the server
and native database dependencies even with default features.

`corbet-foss/cblc` does not exist; the architectural home
[`corbet-libs/cblc`](https://github.com/corbet-libs/cblc) is still a placeholder
without a spend-verification API. Integration uses `ChangeTokenVerifier`,
with no dependency on a scaffold and no local cryptographic token protocol.

## Server API

`server::Pins<S, V>` exposes `pin`, `get` and `change` over a `Store` and
`ChangeTokenVerifier`. `MemoryStore` is for tests; `server::libsql::LibsqlStore`
uses a service-owned `crlt::Db`. Include `server::libsql::SCHEMA` in the service's
ordered migration history before constructing the store. Deploy one database
per community; every row also has a community key and queries use the full
composite primary key. There is no connection or migration counter per leaf.

`Store::compare_exchange` consumes an `AuthorizedChange` witness. Its private
constructor is called only by `Pins::change` after successful spend verification;
adapters can inspect the bound transition but cannot construct or alter the
witness. This closes the direct-storage change bypass found in the security
review. Custom storage adapters must adopt this signature and check the witness's
community. Compile-fail doctests enforce the public API boundary.

```rust,no_run
# #[cfg(all(not(target_arch = "wasm32"), feature = "storage"))]
# async fn example<V: cpns::server::ChangeTokenVerifier>(db: &crlt::Db, verifier: V,
#   initial: cpns::Fingerprint, replacement: cpns::Fingerprint, token: &V::Token)
#   -> Result<(), Box<dyn std::error::Error>> {
use cpns::server::{Pins, libsql::{LibsqlStore, SCHEMA}};
use crlt::Migration;

// For a standalone pins database; a composed service numbers all migrations.
db.migrate(&[Migration::new(1, "pins", SCHEMA)]).await?;
let pins = Pins::new(LibsqlStore::new(db, "community")?, verifier);
let current = pins.pin("member-pseudonym", "restricted-field", initial).await?;
// cblc must already have spent a token bound to this exact transition.
let updated = pins.change("member-pseudonym", "restricted-field", current,
    replacement, token).await?;
assert_eq!(updated.revision, current.revision + 1);
# Ok(())
# }
```

The verifier must authenticate a **completed spend**, for the cpns purpose,
bound to community, member, field, expected digest **and revision**, and new
digest. Verifying a signature on an unspent or unbound token is insufficient.
No permissive production verifier is supplied. Until the cblc adapter exists,
production changes must remain disabled. Initial creation is insert-only and
requires caller authentication and schema authorization.

The revision check prevents concurrent writes and replay even if an old digest
returns. Retries after storage failure re-use the identical spent authorization;
read the current pin to reconcile an uncertain commit. cpns never spends or
refunds a balance token itself. No values, salts, tokens, timestamps or history
are stored. Do not reset revisions or delete/reinsert rows while old
credentials/spends can survive. See the contract for the trusted adapter and
database restoration boundaries.

## Verification

GitHub Actions runs formatting, strict Clippy, real tests and a Wasm target check
on current stable Rust. Do not run Cargo on the workstation. Opening tests cover
independent SHA-256 vectors, invalid salts, wrong openings, framing ambiguity,
binary/Unicode/empty values, freshly salted reversions, v2 context substitution
and version separation. The same storage
contract is exercised against memory and temporary libSQL files, including
concurrent writes, token binding/replay, reopening, isolation, schema constraints,
failure cases and `EXPLAIN QUERY PLAN` assertions on the actual adapter SQL.
The test-only spent receipt ledger exercises the external verifier seam; it is
not a cblc implementation or cryptographic-token test.

The opening tests also execute as `wasm32-unknown-unknown` in headless Chrome,
including real Web Crypto salt generation with `--no-default-features --features
wasm`. The plain Wasm compile check keeps imported-salt consumers free of a
mandatory JavaScript runtime. Dependency choices and upstream test tooling were
rechecked on crates.io/GitHub for the 2026-09-30 security fixes.

The optional real Turso test skips unless **both** `TURSO_URL` and `TURSO_TOKEN`
are nonempty. Only supply a disposable test database: it applies the standalone
schema and writes synthetic rows. Credentials are never read by library code,
stored in this repository or configured in CI. CI retains the resolved dependency
lockfile as an artifact; CI resolves once and all subsequent checks use that
exact snapshot with `--locked`.
Never publish this crate to a registry.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under [LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt) [WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt). See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
