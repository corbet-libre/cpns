#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

python3 .github/check-first-party.py
rustc --version
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
cargo check --locked --target wasm32-unknown-unknown
cargo clippy --locked --target wasm32-unknown-unknown --no-default-features --features wasm --test it -- -D warnings

version=$(jq -r '.packages[] | select(.name == "wasm-bindgen") | .version' dependency-metadata.json)
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="${WASM_BINDGEN_DOWNLOAD_BASE:-https://github.com/wasm-bindgen/wasm-bindgen/releases/download}/${version}"
runner_tmp="${RUNNER_TEMP:-/tmp}/cpns-wasm-runner"
mkdir -p "$runner_tmp"
cd "$runner_tmp"
curl --fail --location --retry 3 --remote-name "$base/$archive"
curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
export PATH="$PWD:$PATH"
cd "$OLDPWD"
export CHROMEDRIVER="$(command -v chromedriver)"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_USE_BROWSER='1'
export WASM_BINDGEN_TEST_TIMEOUT='60'
cargo test --locked --target wasm32-unknown-unknown --no-default-features --features wasm --test it

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
