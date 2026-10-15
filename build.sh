#!/usr/bin/env bash
# Builds collatio.wasm and prints "<sha256> <bytes>".
# The reference build is repro/run.sh (linux/amd64 image pinned by digest); a native build on
# another host can differ in layout (spike/README.md, item 6). Paths are remapped so the module
# does not carry the builder's home, registry or checkout paths.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

export RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$root=/collatio --remap-path-prefix=$rustup_home=/rustup"
export CARGO_TERM_COLOR=never

cd "$root"
cargo build --locked --release --target wasm32v1-none -p collatio >&2
mkdir -p out
cp target/wasm32v1-none/release/collatio.wasm out/collatio.wasm
sum=$( (command -v sha256sum >/dev/null && sha256sum || shasum -a 256) < out/collatio.wasm | cut -d' ' -f1)
echo "$sum $(wc -c < out/collatio.wasm | tr -d ' ')"
