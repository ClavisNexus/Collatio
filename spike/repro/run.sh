#!/usr/bin/env bash
# Two independent linux/amd64 builds (no cache), compared with each other and with out/ (item 6 of spike/README.md).
#   spike/repro/run.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for n in 1 2; do
  rm -rf "$here/repro/out-$n"
  docker build --no-cache --platform linux/amd64 -f "$here/repro/Dockerfile" --output "type=local,dest=$here/repro/out-$n" "$here"
done
sum() { (command -v sha256sum >/dev/null && sha256sum "$1" || shasum -a 256 "$1") | cut -d' ' -f1; }
for v in base probe; do
  a=$(sum "$here/repro/out-1/collatio_spike.$v.wasm"); b=$(sum "$here/repro/out-2/collatio_spike.$v.wasm")
  local_sum=$( [ -f "$here/out/collatio_spike.$v.wasm" ] && sum "$here/out/collatio_spike.$v.wasm" || echo none)
  echo "$v amd64#1=$a amd64#2=$b this-host=$local_sum"
  [ "$a" = "$b" ] || { echo "MISMATCH between the two amd64 builds"; exit 1; }
done
