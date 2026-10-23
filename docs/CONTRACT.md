# cpns contract

`cpns` is the community membership pin library in cvld v0.4. It seals restricted
profile fields; it does not hold profiles, raw gate data, login dates or request
logs. The upstream contract is:

- Per member and restricted field, store a fingerprint `hash(value || salt)`.
- Salts contain at least 128 bits, remain on devices, and are fresh for each change.
- Every change requires a spent change token from `cblc`.
- `pin(member, field, fingerprint)`, `change(member, field, new_fingerprint, token)`
  and `check_opening(fingerprint, value, salt)` are the conceptual operations.
- Reject wrong openings and changes without authorization. Returning to an old
  value with a fresh independent salt must not reveal the repeated value.

## Implemented device protocol

`fingerprint(value, salt)` remains the default v1 and delegates to RustCrypto SHA-256:

```text
SHA-256(
  UTF8("cpns:pin:sha256:v1") || 0x00 ||
  u64be(value.len) || value || u64be(salt.len) || salt
)
```

The digest is exactly 32 bytes. Domain separation and length framing are part
of the protocol; changing them requires a new version. Values are byte strings:
no normalization, serialization or field validation is performed here. The
schema/client must define canonical bytes. The signed community credential
authenticates the digest and its member/field association; a bare digest is not
a credential. `check_opening` delegates comparison to `subtle` and runs without
storage, I/O or randomness, including on `wasm32-unknown-unknown`.

`Salt` accepts at least 16 bytes, offers native 32-byte OS generation, redacts
Debug and zeroizes its owned buffer on drop. It has no serialization or Clone
implementation. On `wasm32-unknown-unknown`, the opt-in `wasm` feature enables
`Salt::generate` with getrandom's `wasm_js` backend and Web Crypto. Failure returns
`RandomnessUnavailable` with no fallback. Without the feature, devices import
their platform randomness; opening checks still require no JavaScript bindings.
Salt bytes may be
borrowed solely for device storage and opening to authorized peers. The caller
controls copies, value buffers and platform crash dumps. Hash working memory
is not promised to be erased.

Freshness and entropy of imported salts cannot be inferred from length. Neither
can the server prove freshness from opaque fingerprints. Honest clients must
generate independent salts even when reverting; the secrecy assumption is at
least 128 unpredictable bits. No test can prove computational indistinguishability;
tests establish distinct fingerprints for fresh salts and failed old openings.

### Optional context binding: v2

The v1 digest binds only the value and salt, not community/member/field. Its
association with those identifiers relies on the signed credential. V1 remains
the default for existing consumers and stored pins.

Opt-in `fingerprint_v2(context, value, salt)` and
`check_opening_v2(fingerprint, context, value, salt)` also bind the three exact
UTF-8 identifiers in `FingerprintContext { community, member, field }`:

```text
SHA-256(
  UTF8("cpns:pin:sha256:v2") || 0x00 ||
  u64be(community.len) || community ||
  u64be(member.len) || member ||
  u64be(field.len) || field ||
  u64be(value.len) || value || u64be(salt.len) || salt
)
```

Lengths count bytes. Each component is separately framed, including empty or
binary values. Identifiers and values are not normalized; the calling protocol
must supply canonical identifiers from authenticated context. Device hashing
does not validate identifiers; server keys retain their constraints below.
The cryptographic primitive, constant-time comparison, and salt requirements
are unchanged. Context binding does not permit salt reuse or replace credentials.

`Fingerprint` and storage still contain exactly 32 untagged digest bytes. The
owning signed credential/schema protocol must authenticate the version (as a
protocol-wide choice or an explicit signed field) and use the corresponding
opening function. There is no autodetection or fallback. Choosing v2 for an
existing pin requires an ordinary token-authorized change with a fresh salt;
cpns performs no automatic rewrite, migration, or version inference. Revisions
and spend binding continue to protect transitions for either digest version.
Frozen vectors and substitution tests cover both versions natively and on Wasm.

## Server integration boundary

`Pins<S, V>` exposes:

- `pin(member, field, fingerprint) -> Pin`: insert revision one. A duplicate,
  even with the same digest, returns `AlreadyPinned` and never overwrites.
- `get(member, field) -> Option<Pin>`: read the current digest and revision.
- `change(member, field, expected_pin, new_fingerprint, token) -> Pin`: verify a
  spent authorization, then compare-and-swap exactly the old digest and revision.
  Success increments the revision once. A stale state returns `Conflict`; a
  missing pin returns `NotPinned`. An identical replacement returns `Unchanged`.

Identifiers are opaque, case-sensitive UTF-8 strings of 1–1024 bytes without
NUL. No identifiers or fingerprint bytes appear in cpns Debug/error output.
Revisions are positive, at most `i64::MAX`, and may never wrap or reset.
Fingerprint imports enforce 32 bytes by type; storage also validates blob type,
length and positive integer revisions. Changing an exhausted revision fails.

`ChangeTokenVerifier` is the minimal local cblc seam. It MUST verify an
irreversible, completed spend for the cpns change purpose bound to all of:
community, member, field, old fingerprint, old revision, new fingerprint.
Each spent token authorizes exactly one such transition. Evidence must remain
verifiable for identical retries; no success is allowed for unspent, invalid,
unbound, revoked or otherwise inadmissible evidence, or verifier outages.
No production verifier is supplied. In particular, there is no accept-all mode.
The test-only in-memory spent receipt ledger is an external integration fixture,
not a claim to implement or test cblc cryptography.

The service obtains a bound spend from cblc *before* calling change. cpns does
not atomically debit cblc: a spend can succeed and the subsequent pin write fail.
Re-use that same authorization for the same transition. Never refund or reuse it
for a different transition based merely on a cpns timeout. If the pin already
equals the target at expected revision + 1, the transition is applied; if the
old pin remains, retry. A different/later state is a conflict requiring caller
reconciliation. cpns cannot prove which request won when two independent valid
authorizations name an identical transition. Uncertain commit errors are reported
as `Storage`, never as guaranteed rollback. Cancellation during verification
makes no write; cancellation during commit has the same reconciliation boundary.

All errors are coarse data-free categories. No driver error source, token or
opening is retained. cpns emits no logs. The service must also disable dependency
SQL/HTTP debug tracing and request logging.

## Storage and trust

`Store` is a trusted fixed-community capability. Its implementations must
provide insert-only creation and atomic compare-and-swap. `compare_exchange`
consumes `AuthorizedChange`, an immutable witness with a private constructor
called only in `Pins::change`, after `ChangeTokenVerifier::verify_spent` succeeds.
Its read-only `change()` accessor exposes the exact verified transition to
adapters; there is no public constructor, mutable accessor, Clone or deserializer.
An ordinary `Change` cannot authorize a write. Adapters must check the witness's
community against their fixed scope and atomically check digest and revision.
Compile-fail doctests cover direct writes and witness construction. This closes
the public storage bypass identified in the 2026-09-30 security review. The
public low-level trait remains a trusted service integration surface.

Native `MemoryStore` is a real implementation
with a mutex and ordered map, shared by its clones. It is for tests, not for
durable credentials: losing its state would reset revisions.

`LibsqlStore` accepts a service-owned `crlt::Db`, follows crlt's main
branch with a reproducible locked revision, and uses scoped transactions. No direct libSQL
dependency or raw connection is exposed by cpns. The service includes `SCHEMA`
in its complete numbered migration history; the library does not reserve global
migration numbers or apply a separate history that could clash with other leaves.

```text
cpns_pins(
  community_id TEXT, member_id TEXT, field_id TEXT,
  fingerprint BLOB(32), revision INTEGER,
  PRIMARY KEY (community_id, member_id, field_id)
) WITHOUT ROWID
```

One DB per community is a deployment requirement. Community keys are additionally
in every row and primary key, and crlt injects the scope in every query. Tests
deliberately put two scopes in one DB to check isolation. Reads, pre-insert
existence checks and conditional updates all search the full primary key;
inserts need no scan. crlt enforces indexed query plans, and tests assert the
full lookup key using `EXPLAIN QUERY PLAN` on the adapter's exact statements.
Only current digests and revisions are stored; no salt, value, token, timestamps,
login/request log or change history is recorded by cpns. crlt has a schema-only
migration ledger. Database WAL, backups and storage media can retain overwritten
digests; logical current-state storage does not promise forensic erasure.

Member authentication, allowed fields and value validation, canonical encoding,
signed credentials, authorization to create initial pins and DB routing belong
to the caller. A peer must verify a credential before trusting its fingerprint.
Opening verification belongs on devices; never send raw fields/salts to the
permanent service. The server cannot attest salt entropy/freshness, or whether
an opaque digest represents any valid opening, without additional proofs.

There is deliberately no delete/reset API. Deletion/re-registration, restored
old database snapshots and new member incarnations must not revive outstanding
authorizations. Safe lifecycle/restore handling needs coordinated cblc epochs or
invalidation before it can be added. A malicious storage/verifier implementation
or a service directly rewriting its DB is outside this library's trust boundary.

## Verification and remaining integration

The libSQL-specific `Pins::change_current` additionally holds the actual immediate
write transaction across an application's read-only current-authority checks.
It applies the exact revision/fingerprint CAS, checks current owners under that
lock, checks the caller's live exclusive deadline at the commit cut, and checks
again after return. A refused or cancelled pre-commit check rolls back the pin;
a failed post-commit check returns the uncertain `Error::Storage` and requires
reading the current pin. The samples bracket the commit await; they do not
guarantee physical storage completion before authority expiry.
The caller retains its member lease and uses genuine owners against the same
database, without nested writes. Separate pooled reads require another available
connection; a one-connection pool refuses at its configured CRLT deadline. This
hook does not establish membership or verify native accounting proofs itself.

CI runs formatting, strict Clippy, native tests (default and without storage),
checks the device crate for `wasm32-unknown-unknown` without JavaScript support,
and runs the opening suite on that target in headless Chrome with `wasm` enabled.
The browser suite includes real `Salt::generate` calls and fresh-salt reversions;
the same frozen independent SHA-256 vectors run natively and on Wasm.
Both storage adapters reject tokens spent for another community through
`Pins::change`, leaving current state unchanged. Real libSQL file tests cover
replay, races across independent database
handles, persistence, migration idempotence, corruption rejection and scoping.
Turso tests require both URL and token in the environment and otherwise skip;
no CI secrets are used. The optional remote test requires a disposable DB.

Open integration: security-review the cblc verifier (implemented as
`PinSpendVerifier` in cblc `src/pins.rs`) against this
binding/retry contract, including the interaction of member/field binding with
cblc unlinkability; choose canonical encodings and authenticated v2 negotiation
in cshm/cgrd; integrate device salt
storage and signed-credential handling in their owning crates; coordinate safe
lifecycle and database rollback handling. The 2026-09-30 review prompted these
fixes; it is not a comprehensive independent cryptographic audit.

## License

LGPL-3.0-only WITH LGPL-3.0-linking-exception. No GPL-only or AGPL-only dependency.
