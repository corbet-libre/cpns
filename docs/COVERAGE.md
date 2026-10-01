# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. The sole proposed defensive-line exclusion below requires manager review.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

## Emitted source metric

The acceptance metric is now 100% of upstream LLVM LCOV's emitted production
source line counters (DA) and branch counters (BRDA), from the same execution as
the retained raw JSON. This is source coverage, not every generic instantiation.
LLVM JSON and LCOV summary totals can count generic copies differently from
the merged source records. The original JSON checker remains diagnostic code;
its stricter instantiation totals are not described as passed.

The source gate requires a nonempty report, an exact file inventory matching the
companion JSON, matching raw summary metadata, complete emitted branch counts
and no duplicate, unknown or zero counters. Only the source-pinned defensive-line exception below is configured.
Actual browser/device execution remains separate from native coverage.

## Unreachable community error mapping

One native line is excluded: `src/server/libsql.rs:45`, the closure body mapping
`Db::community` errors. `LibsqlStore::new` has already called `validate_key`, which
rejects empty strings, NUL and keys longer than1024 bytes. Current `crlt`
`6ca3bd1035fcf17c2c88cdae3ed913da49740252` `src/lib.rs:185–195` rejects only empty
strings and NUL. The constructor clones its connection capability and performs
no I/O. Every error input is therefore refused before the defensive closure.
The production mapping remains unchanged for future upstream errors.

The exception is limited to that exact source line and native target. It cannot
exclude branches, move to changed source, omit an actual report location or
remain enabled once the line executes. JSON, LCOV and annotated reports must
agree on complete inventories before applying it. The committed manifest gives
the proof and dependency evidence; this exception remains subject to Opus review.
An upstream constructor change requires re-review. No other storage error is
excluded: real libSQL failures, malformed imported rows and an incompatible
required-column schema exercise the reachable refusal paths. The last pre-fix
run retained333/335 lines and32/32 branches, not full coverage.
