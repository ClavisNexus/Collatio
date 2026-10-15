# Collatio

The verifier for [Clavis](https://clavis.nexus) evidence: receipts of passkey signatures, delegation records, account and organisation chains, and the ledger (signed notes, checkpoints, inclusion and consistency proofs, bundles with TSA tokens).

Collatio is one WebAssembly module, named by the SHA-256 of its bytes. Clavis, the app SDKs and anyone else run the same module, so the same evidence gets the same answer everywhere. It takes no imports and keeps no clock: the caller passes the evidence, the trust root and the time.

*Collatio* is Latin for collation: comparing a copy with the original. The module compares what it is given with the signer's signature, the keys and the ledger. It does not vouch for anything itself.

## Status

Under construction; nothing is released. Done so far:

- the strict JSON reader (unique keys, no lone surrogates, depth limit), RFC 8785 canonical form, Base64URL, digests and the envelope challenge, checked byte for byte against the Clavis TypeScript implementation they replace (`vectors/pregenesis`);
- the method `webauthn@1` (COSE keys for ES256 and EdDSA, authenticator data, `clientDataJSON`, the origin rule), checked against the TypeScript implementation on 900 real and mutated assertions;
- text rules, `shown@1`, key records (`key.bound@1`, `key.unbound@1`) and salted commitments;
- the ledger core: signed notes (Ed25519), checkpoint and receipt bodies, leaves, and RFC 9162 inclusion and consistency proofs;
- RFC 3161 time-stamp tokens: a strict DER reader, X.509 certificates, CMS SignedData, ESS signing-certificate attributes, chains to the registry roots at genTime, and RSASSA-PKCS1-v1_5 written on crypto-bigint (no `rsa` crate). Checked on the two real tokens Clavis uses and 800 single-byte flips of them: Collatio never accepts what the TypeScript refused, and refuses 10 flips the TypeScript let through (corrupted headers and unused certificates). RSA also passes Project Wycheproof;
- the statement field kinds, checked against the TypeScript reader on 1,253 kind strings and 2,040 values;
- the genesis formats drafted in `FORMATS.md` (some points open for review): the envelope with the new `aud`, `registry@1`, `dimension@1`, the trust chain (Master pin → sealer nomination → aggregated JWKS and `catalog@1`), and holder and app receipts with `accepted@1`, `ledger.receipt@1` and `key.opening@1`;
- the operations `trust`, `proof`, `receipt`, `app_receipt`, `ledger_note`, `inclusion` and `consistency` (`ABI.md`), checked on 71 calls written by an independent issuer (`tools/genesis-vectors.mjs`, node:crypto only) and run both natively and as WebAssembly.

Not yet: delegation records, event chains, the genesis ledger evidence bundle, and the JavaScript and Go hosts.

Dependencies are pinned in `Cargo.lock` and must be at least 14 days old (`node tools/check-release-age.mjs`).

## Layout

| Path | |
|---|---|
| `crates/collatio` | The verifier. `no_std` + `alloc` for `wasm32v1-none`; std on the host for tests |
| `ABI.md` | `collatio-abi@1`: how a host calls the module, the operations and the reasons |
| `FORMATS.md` | The byte-level formats from Clavis genesis on (draft) |
| `vectors/` | Test vectors. `pregenesis/` holds reference answers from the TypeScript implementation; `genesis/` holds calls and answers from `tools/genesis-vectors.mjs` |
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
