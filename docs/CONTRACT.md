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

`fingerprint(value, salt)` delegates to RustCrypto SHA-256:

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
implementation. Browser clients import Web Crypto output. Salt bytes may be
borrowed solely for device storage and opening to authorized peers. The caller
controls copies, value buffers and platform crash dumps. Hash working memory
is not promised to be erased.

Freshness and entropy of imported salts cannot be inferred from length. Neither
can the server prove freshness from opaque fingerprints. Honest clients must
generate independent salts even when reverting; the secrecy assumption is at
least 128 unpredictable bits. No test can prove computational indistinguishability;
tests establish distinct fingerprints for fresh salts and failed old openings.

## Server integration boundary

The next implementation step adds community-scoped storage through `crlt`, an
in-memory adapter, and a verifier trait for `cblc`. No production token verifier
is available yet. Initial pin creation must never overwrite an existing pin;
changes require verification of an already-spent, operation-bound token plus
an atomic revision check. Only the current digest and revision may be stored;
no salt, value, token, timestamp or change history belongs in the pin row.

## License

LGPL-3.0-only WITH LGPL-3.0-linking-exception. No GPL-only or AGPL-only dependency.
