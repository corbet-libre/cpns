//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/it/common` holds the shared store fixtures.
// `server` (and this shared fixture) exists only on native targets.
#[cfg(not(target_arch = "wasm32"))]
mod common;
mod diagnostics;
mod openings;
mod storage;
