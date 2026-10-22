# Collatio

The verifier for [Clavis](https://clavis.nexus) evidence: receipts of passkey signatures, delegation records, account and organisation chains, and the ledger (signed notes, checkpoints, inclusion and consistency proofs, bundles with TSA tokens).

Collatio is one WebAssembly module, named by the SHA-256 of its bytes. Clavis, the app SDKs and anyone else run the same module, so the same evidence gets the same answer everywhere. It takes no imports and keeps no clock: the caller passes the evidence, the trust root and the time.

*Collatio* is Latin for collation: comparing a copy with the original. The module compares what it is given with the signer's signature, the keys and the ledger. It does not vouch for anything itself.

## Status

The reference module, from `repro/run.sh`, is `sha256:knnwNOIOIHDFLS8Gp7UsnnFjlneACn4I5NLCkl-mTvI`. `@clavis.nexus/collatio` ships that module from 1.0.1.

`v1.0.0` (`go/v1.0.0` on the same commit) recorded `sha256:FPh2AxvhGnU5XiO69qivINTC7WGW_4_IzW_iPOdGyKc`. `repro/run.sh` does not reproduce that file.

Done so far:

- the strict JSON reader (unique keys, no lone surrogates, depth limit), RFC 8785 canonical form, Base64URL, digests and the envelope challenge, checked byte for byte against the Clavis TypeScript implementation they replace (`vectors/pregenesis`);
- the method `webauthn@1` (COSE keys for ES256 and EdDSA, authenticator data, `clientDataJSON`, the origin rule), checked against the TypeScript implementation on 900 real and mutated assertions;
- text rules, `shown@1`, key records (`key.bound@1`, `key.unbound@1`) and salted commitments;
- the ledger core: signed notes (Ed25519), checkpoint and receipt bodies, leaves, and RFC 9162 inclusion and consistency proofs;
- RFC 3161 time-stamp tokens: a strict DER reader, X.509 certificates, CMS SignedData, ESS signing-certificate attributes, chains to the registry roots at genTime, and RSASSA-PKCS1-v1_5 written on crypto-bigint (no `rsa` crate). Checked on the two real tokens Clavis uses and 800 single-byte flips of them: Collatio never accepts what the TypeScript refused, and refuses 10 flips the TypeScript let through (corrupted headers and unused certificates). RSA also passes Project Wycheproof;
- the statement field kinds, checked against the TypeScript reader on 1,253 kind strings and 2,040 values;
- the genesis formats in `FORMATS.md`: the envelope with the new `aud`, `registry@1`, `dimension@1`, the trust chain (Master pin → sealer nomination → aggregated JWKS and `catalog@1`), holder and app receipts with `accepted@1`, `ledger.receipt@1` and `key.opening@1`, delegation records, event chains (`event@1`, `event.content@1`, `state.snapshot@1`) and the ledger evidence bundle `ledger.bundle@1`;
- every operation of the first release (`ABI.md`), checked on 142 calls written by an independent issuer (`tools/genesis-vectors.mjs`, node:crypto only) and run both natively and as WebAssembly.

- the JavaScript host (`js/`, npm `@clavis.nexus/collatio`, no dependencies) and the Go host (`go/`, `github.com/clavisnexus/collatio/go` on wazero). Both pass the same conformance scenarios (`conformance/hosts-1.json`: ABI version and export checks, recovery after a trap, replacing an instance over its memory limit, running only catalog-listed unrevoked modules, following a revoked verifier to its successor, marking a stale catalog) and give the 142 answers above.

The aggregated chain head `state.heads@1` is specified when aggregation is built.

Dependencies are pinned in `Cargo.lock` and must be at least 14 days old (`node tools/check-release-age.mjs`).

## Layout

| Path | |
|---|---|
| `crates/collatio` | The verifier. `no_std` + `alloc` for `wasm32v1-none`; std on the host for tests |
| `ABI.md` | `collatio-abi@1`: how a host calls the module, the operations and the reasons |
| `FORMATS.md` | The byte-level formats from Clavis genesis on |
| `js/` | `@clavis.nexus/collatio`: the JavaScript host (`npm test` after `./build.sh`) |
| `go/` | `github.com/clavisnexus/collatio/go`: the Go host on wazero (`go test ./...` after `./build.sh`) |
| `conformance/` | Host scenarios both hosts must pass, and the small modules they run (`tools/conformance-modules.mjs`) |
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

## Publish

`js/` is the registry package, published from `.github/workflows/publish.yml` through npm trusted publishing; no npm token is used. The catalog records `vX.Y.Z`.

1. Through a pull request to `main`, raise `version` in `js/package.json` and the digest in `js/README.md` if the module changed.
2. Once its checks on `main` have passed, tag the merged commit `go/vX.Y.Z` and `vX.Y.Z`, and push `go/vX.Y.Z` first.

   ```bash
   git tag go/v1.0.2 && git tag v1.0.2
   git push origin go/v1.0.2 && git push origin v1.0.2
   ```

3. The workflow runs the crate age check, the tests and the reference build, packs the module only when `repro/run.sh` has left two matching files and the packed README names it, and stages the package on npm.
4. Check that the commit in the run's summary is on `main`, and that the integrity of the `stage` job matches the one npmjs.com shows under Staged Packages. Then approve it there with 2FA. The trusted publisher on npm allows staging only.

## License

MIT. `collatio.wasm` also contains the Rust crates listed, with their licenses, in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) (shipped in the npm package). After changing dependencies, run `cargo fetch --target wasm32v1-none` and `node tools/third-party-notices.mjs`.
