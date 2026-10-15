# Collatio spike

A small verifier built only to measure what public information does not tell us before writing Collatio (Nexus `docs/architecture/genesis.md` §18.10). It is not the verifier and nothing depends on it.

It verifies P-256 ECDSA, Ed25519 and RSASSA-PKCS1-v1_5 (RSA on `crypto-bigint`, not the `rsa` crate, §18.8), formats numbers the RFC 8785 way, and exposes `collatio-abi@1` (§18.3) so the hosts can be reused.

| Path | |
|---|---|
| `verifier/` | Rust, `wasm32v1-none`, `no_std` + `alloc`, `panic = "abort"`, no imports |
| `build.sh` | `./build.sh base` or `./build.sh probe` (adds X.509 and CBOR parsing to check they build). Remaps paths; prints the SHA-256 |
| `host/collatio.mjs` | JS host (Node and Workers). Rebuilds the instance after a trap |
| `host/differential.mjs` | Wycheproof, random keys and mutated signatures against `node:crypto`, 1,000,000 doubles against ECMAScript, trap and memory |
| `host/bench.mjs` | Timing in Node; writes `vectors/bench.json` once |
| `host/record.mjs` | Records calls and exact answers to `vectors/answers.jsonl` |
| `go/` | wazero host limited to WebAssembly 1.0 features; replays `answers.jsonl` |
| `worker/` | Spike Workers (single verifier; eight bundled verifiers), `measure.sh`, `analyze.mjs` |
| `repro/` | Two `linux/amd64` builds from a pinned image, compared with each other and with this host |
| `vectors/wycheproof/` | C2SP/wycheproof `testvectors_v1` at a pinned commit (see `SOURCE`, Apache-2.0) |

## Run

```bash
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
spike/build.sh base && spike/build.sh probe
node spike/host/differential.mjs
node spike/host/bench.mjs
node spike/host/record.mjs > spike/vectors/answers.jsonl
(cd spike/go && go run . ../out/collatio_spike.wasm ../vectors/answers.jsonl)
spike/repro/run.sh                      # needs Docker
```

The deployed measurement needs Cloudflare credentials and is run by a person: see the header of `worker/measure.sh`. The Workers are not bound to any route, resource, secret or key, and are deleted after measuring.

## Results

Local on 2026-10-14; Workers (the spike Worker on a `workers.dev` route, one `measure.sh` run) and the two `linux/amd64` builds on 2026-10-15.

Toolchain: rustc 1.95.0 (pinned by `verifier/rust-toolchain.toml`), Node 22, Go 1.27.1, wazero 1.12.0, wrangler 4.89.0.

| Item (§18.10) | Result |
|---|---|
| 7. Crates on `wasm32v1-none` `no_std` | Build: `p256` 0.14.0, `sha2` 0.11.1, `crypto-bigint` 0.7.5, `ed25519-dalek` 3.0.0, `serde_json` 1.0.154 (`alloc`), `base64ct` 1.8.3, `ryu-js` 1.0.3, `dlmalloc` 0.2.14 (`global`); probe: `x509-cert` 0.3.0, `minicbor` 2.3.0. `cms` exists only as 0.3.0-rc.0 for this `der` line, so TSA tokens (CMS SignedData) would be parsed with `der`/`x509-cert` directly. `p256` precomputed tables need `critical-section` or `std`, so they are off; P-256 verification is therefore slower than Ed25519 |
| 1. Size | base 295,137 B (gzip 115,648); probe 359,181 B (gzip 132,734). Deployed: 295.31 KiB / gzip 116.81 KiB |
| 9. Several verifiers | Eight probe copies in one Worker deployed (2,812 KiB / gzip 1,050 KiB); Cloudflare accepted it, so startup stayed under its limit, and all eight answered. wrangler 4.89.0 does not print the startup time |
| 2. CPU per verification | **Workers (tail `cpuTime`, median of 7, (n=101 − n=1)/100)**: P-256 1.04 ms, Ed25519 0.24 ms, RSA-2048 0.90 ms, RSA-4096 3.13 ms, receipt (P-256 ×2 + Ed25519) 2.52 ms, TSA bundle (receipt + RSA-4096 ×2 + RSA-2048) 10.3 ms. About 2.5–3× the local numbers. Node (V8, steady): P-256 0.36 ms, Ed25519 0.08 ms, RSA-2048 0.23 ms, RSA-4096 0.86 ms. Local workerd (wall time incl. loop): P-256 ≈0.41 ms, Ed25519 ≈0.08 ms, RSA-2048 ≈0.29 ms, RSA-4096 ≈1.1 ms, receipt (P-256 ×2 + Ed25519) ≈0.94 ms, TSA bundle (receipt + RSA-4096 ×2 + RSA-2048) ≈3.5 ms. First request after the deploy 61 ms to first byte, warm 38 ms (client-side, both new TLS connections) |
| 3. Trap | After an intentional trap, a rebuilt instance answers again: Workers, Node, local workerd and wazero |
| 4. Memory | Linear memory grows once and stays: Node 1.1 → 5.2 MiB after 200 inputs of 4 MiB; workerd and Workers 1.1 → 9.6 MiB after 50 large inputs, unchanged after more. Inputs over 4 MiB are refused before parsing |
| 5. Agreement | Wycheproof: RSA 2048/3072/4096 × SHA-256/384/512 and P-256 (DER and P1363) — no valid signature refused, no invalid one accepted; one "acceptable" case per RSA file (DigestInfo without NULL) is refused; RSA-8192 keys are refused by the size policy. Random keys with mutated signatures agree with `node:crypto` (RSA 360, P-256 400, Ed25519 200). wazero replays 3,360 calls with byte-identical answers |
| 6. Reproducible build | Two independent `linux/amd64` builds from the pinned image (`repro/run.sh`, `--no-cache`) give the same hashes: base `7857d485…722d`, probe `e0c42f40…b529`. A native build on an `aarch64-apple-darwin` host with the same rustc gives the same size and strings but a different layout, most likely because Cargo hashes `rustc -vV` (which names the host) into symbol metadata. So the reference build is the container, on any host. Without path remapping, panic locations carry the registry and home paths |
| 8. RFC 8785 numbers | `ryu-js` builds `no_std`; 999,861 doubles (random bit patterns, random decimals, integers, edge cases) match ECMAScript `String(x)` |

Findings for the design:

- `collatio-abi@1` says `abi_version` is an i32 global. Rust exports a `static` as its address, not its value, so the spike exports `abi_version() -> i32`. The ABI document should say function.
- Builds must remap paths (`--remap-path-prefix`), or the hash depends on where the registry and the checkout live.
- The local `workerd` in wrangler 4.89.0 accepts compatibility dates up to 2026-05-14 (the spike uses 2026-05-01). The latest wrangler is 4.151.0.

- The first native build, and the one deployed to Workers, used the machine's default toolchain (stable 1.99.0), not 1.95.0. `verifier/rust-toolchain.toml` now pins the toolchain. The 1.95.0 build passes the differential tests again and returns byte-identical answers to all 3,360 calls recorded from the 1.99.0 build.
- `isolate.age_ms` in the Worker's answers is meaningless: `Date.now()` at module scope is 0 on Workers.

All nine items pass. The measured startup time itself is not known: wrangler 4.89.0 did not print it for either Worker.
