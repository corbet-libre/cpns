# cpns agent instructions

Write all code comments and documentation in English. Owned code forbids unsafe
Rust (`#![forbid(unsafe_code)]`, `src/lib.rs:2`).

## Build and test (lane: `~/agents/scratch/cbuild <lane> ...`)

- `fmt -p cpns -- --check`
- `test -p cpns` (lib 13 + diagnostics 2 + openings 10 + storage 15 + doc 5,
  exit 0; `--locked` needs CI's resolve refresh)
- `test -p cpns --no-default-features` (3 + 2 + 10 + 5 + 5, exit 0)
- `clippy -p cpns --all-targets -- -D warnings`
- `check -p cpns --target wasm32-unknown-unknown`
- `clippy -p cpns --target wasm32-unknown-unknown --no-default-features
  --features wasm --test it -- -D warnings`
- wasm exec: `test -p cpns --target wasm32-unknown-unknown
  --no-default-features --features wasm --test it` with
  `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner`
  (openings 10 + diagnostics 1, headless Chrome, exit 0)
- CI-only (Crow `.ci/verify.sh`): nightly `llvm-cov` 100% line+branch gate
  (`docs/COVERAGE.md`); Turso test skips without `TURSO_URL`/`TURSO_TOKEN`

## Hard invariants (each with its enforcing test)

- v1/v2 digests are frozen byte layouts; no autodetection, fallback or silent
  migration (`docs/CONTRACT.md:17-32,78-85`): `openings::matches_independent_v1_vectors`,
  `openings::matches_independent_v2_vectors`, `openings::framing_separates_identical_raw_concatenations`
  (same vectors run natively and on wasm).
- Salts hold >= 16 bytes, redact Debug and zeroize on drop
  (`docs/CONTRACT.md:34-43`): `openings::enforces_salt_length_and_accepts_binary_and_empty_values`,
  `diagnostics::salt_errors_are_static_and_have_no_sensitive_source`.
- `Store::compare_exchange` consumes only the `AuthorizedChange` witness built
  inside `Pins::change` after a verified spend; no public constructor
  (`docs/CONTRACT.md:133-142`): compile-fail doctests in `src/server/mod.rs`.
- Revisions are positive and never wrap or reset; stale state is `Conflict`,
  missing is `NotPinned`, identical is `Unchanged` (`docs/CONTRACT.md:95,101`):
  `memory_round_trip` / `database::libsql_round_trip`,
  `memory_rejects_invalid_inputs` / `database::libsql_rejects_invalid_inputs`,
  `memory_serializes_competing_changes` /
  `database::separate_database_handles_serialize_competing_changes`.
- Every change needs a spent token bound to community/member/field/old/new
  (`docs/CONTRACT.md:105-112`): `verifier_failure_cannot_change_a_pin`,
  `memory_cancellation_before_verification_keeps_current_pin` /
  `database::libsql_cancellation_before_verification_keeps_current_pin`,
  `database::retry_after_storage_timeout_reuses_the_same_spent_authorization`.
- No identifiers or fingerprint bytes in Debug/error output; cpns emits no logs
  (`docs/CONTRACT.md:100,126-128`): `diagnostics::*`, `server_errors_are_static_and_have_no_driver_source`.
- Only digests and revisions are stored: no salt, value, token, timestamp or
  history; no delete/reset API (`docs/CONTRACT.md:128-129,177-183`).
- Statements use the full composite primary key; two scopes in one DB stay
  isolated (`docs/CONTRACT.md:154-167`):
  `server::libsql::tests::exact_statement_plans_use_the_full_primary_key`,
  `database::communities_are_isolated_even_in_one_database`.
- LGPL-3.0-only WITH linking exception (`LICENSE.md`, `deny.toml`).

Pointers: `docs/CONTRACT.md`, `docs/COVERAGE.md`.
