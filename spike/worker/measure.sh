#!/usr/bin/env bash
# Measures the deployed spike Worker (genesis.md §18.10 items 1–4). Run by a person with
# Cloudflare credentials, after deploying:
#   wrangler deploy --config spike/worker/wrangler.jsonc        # note "Worker Startup Time" and "Total Upload"
#   spike/worker/measure.sh https://clavis-collatio-spike.<subdomain>.workers.dev
# Then the multi-verifier Worker (item 9):
#   node spike/worker/scripts/make-copies.mjs 8
#   wrangler deploy --config spike/worker/wrangler.multi.jsonc  # note "Worker Startup Time" and "Total Upload"
#   curl -s https://clavis-collatio-spike-multi.<subdomain>.workers.dev/run?all=1
# Delete both afterwards:
#   wrangler delete --config spike/worker/wrangler.jsonc
#   wrangler delete --config spike/worker/wrangler.multi.jsonc
set -euo pipefail
base="${1:?workers.dev URL}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wrangler="${WRANGLER:-wrangler}"
out="$here/../results/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$out"

$wrangler tail --config "$here/wrangler.jsonc" --format json > "$out/tail.jsonl" 2> "$out/tail.err" &
tail_pid=$!
trap 'kill $tail_pid 2>/dev/null || true' EXIT
sleep 10

# First request after the deploy, then the same request warm.
curl -s -o /dev/null -w '{"first_ttfb_s":%{time_starttransfer},' "$base/info" > "$out/first.json"
curl -s -o /dev/null -w '"warm_ttfb_s":%{time_starttransfer}}\n' "$base/info" >> "$out/first.json"

for c in p256 ed25519 rsa2048 rsa4096 receipt bundle_tsa; do
  for n in 1 101; do
    for r in 1 2 3 4 5 6 7; do
      curl -s "$base/run?case=$c&times=$n&r=$r" >> "$out/runs.jsonl"
      echo >> "$out/runs.jsonl"
    done
  done
done
curl -s "$base/trap" > "$out/trap.json"
curl -s "$base/memory" > "$out/memory.json"
curl -s "$base/info" > "$out/info.json"

sleep 15
kill "$tail_pid" 2>/dev/null || true
node "$here/analyze.mjs" "$out" | tee "$out/summary.json"
