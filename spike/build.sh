#!/usr/bin/env bash
# Builds the spike verifier and prints its SHA-256.
#   spike/build.sh [base|probe]
# Paths are remapped so panic locations do not carry the builder's home or registry path
# (genesis.md §18.6: two independent builds must give the same hash).
set -euo pipefail

variant="${1:-base}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$here/verifier"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

export RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$crate=/src --remap-path-prefix=$rustup_home=/rustup"
export CARGO_TERM_COLOR=never

features=()
if [ "$variant" = "probe" ]; then
  features=(--features probe)
fi

cd "$crate"
cargo build --locked --release --target wasm32v1-none ${features[@]+"${features[@]}"} >&2
mkdir -p "$here/out"
cp target/wasm32v1-none/release/collatio_spike.wasm "$here/out/collatio_spike.$variant.wasm"
if [ "$variant" = "base" ]; then
  cp "$here/out/collatio_spike.base.wasm" "$here/out/collatio_spike.wasm"
fi
size=$(wc -c < "$here/out/collatio_spike.$variant.wasm" | tr -d ' ')
gz=$(gzip -9c "$here/out/collatio_spike.$variant.wasm" | wc -c | tr -d ' ')
sum=$( (command -v sha256sum >/dev/null && sha256sum || shasum -a 256) < "$here/out/collatio_spike.$variant.wasm" | cut -d' ' -f1)
echo "$variant $sum $size $gz"
