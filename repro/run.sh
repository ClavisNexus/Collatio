#!/usr/bin/env bash
# Two independent reference builds (no cache); their hashes must match.
#   repro/run.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sums=()
for n in 1 2; do
  rm -rf "$root/repro/out-$n"
  docker build --no-cache --platform linux/amd64 -f "$root/repro/Dockerfile" --output "type=local,dest=$root/repro/out-$n" "$root"
  sums+=("$( (command -v sha256sum >/dev/null && sha256sum || shasum -a 256) < "$root/repro/out-$n/collatio.wasm" | cut -d' ' -f1)")
done
echo "build 1: ${sums[0]}"
echo "build 2: ${sums[1]}"
[ "${sums[0]}" = "${sums[1]}" ] || { echo "MISMATCH"; exit 1; }
