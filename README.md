# Collatio

The verifier for [Clavis](https://clavis.nexus) evidence: receipts of passkey signatures, delegation records, account and organisation chains, and the ledger (signed notes, checkpoints, inclusion and consistency proofs, bundles with TSA tokens).

Collatio is one WebAssembly module, named by the SHA-256 of its bytes. Clavis, the app SDKs and anyone else run the same module, so the same evidence gets the same answer everywhere. It takes no imports and keeps no clock: the caller passes the evidence, the trust root and the time.

*Collatio* is Latin for collation: comparing a copy with the original. The module compares what it is given with the signer's signature, the keys and the ledger. It does not vouch for anything itself.

## Status

Under construction; nothing is released. Done so far:

- the strict JSON reader (unique keys, no lone surrogates, depth limit), RFC 8785 canonical form, Base64URL, digests and the envelope challenge, checked byte for byte against the Clavis TypeScript implementation they replace (`vectors/pregenesis`);
- the method `webauthn@1` (COSE keys for ES256 and EdDSA, authenticator data, `clientDataJSON`, the origin rule), checked against the TypeScript implementation on 900 real and mutated assertions;
- the ABI (`ABI.md`) with its fixed list of reasons; no operation answers yet.

Dependencies are pinned in `Cargo.lock` and must be at least 14 days old (`node tools/check-release-age.mjs`).

## Layout

| Path | |
|---|---|
| `crates/collatio` | The verifier. `no_std` + `alloc` for `wasm32v1-none`; std on the host for tests |
| `ABI.md` | `collatio-abi@1`: how a host calls the module, the operations and the reasons |
| `vectors/` | Test vectors. `pregenesis/` holds reference answers from the TypeScript implementation |
| `build.sh` | Builds `out/collatio.wasm` and prints its hash |
| `repro/` | The reference build: two `linux/amd64` builds from a pinned image must give the same hash |
| `spike/` | The measurement spike that chose Rust and WebAssembly (results in `spike/README.md`) |

## Build

```bash
./build.sh
cargo test
repro/run.sh   # the reference build; needs Docker
```

The toolchain is pinned in `rust-toolchain.toml` and dependencies in `Cargo.lock`. Released modules are built with `repro/run.sh`, on any host.

## License

MIT
