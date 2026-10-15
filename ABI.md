# collatio-abi@1

How a host runs `collatio.wasm`. The JavaScript and Go hosts implement this page separately, so it is the contract between them and the module. A change that breaks it is `collatio-abi@2`, with a new `abi_version`, and hosts refuse a module whose version they do not know.

## Module

- WebAssembly 1.0 with mutable globals (`wasm32v1-none`). No imports: instantiate with an empty import object.
- Exports:

| Export | Type | |
|---|---|---|
| `memory` | memory | Linear memory. It grows and never shrinks. |
| `abi_version` | `() -> i32` | Returns `1`. A function, not a global: Rust exports a `static` as its address. |
| `alloc` | `(len: i32) -> i32` | Returns a pointer to `len` writable bytes, or 0 when memory is exhausted. |
| `free` | `(ptr: i32, len: i32)` | Returns a buffer from `alloc` or from `verify`. |
| `verify` | `(in_ptr: i32, in_len: i32) -> i32` | Runs one call. Returns a pointer to the answer. |

Other exports (the linker's `__data_end` and `__heap_base`) are not part of the ABI; hosts ignore them.

## A call

1. `p = alloc(n)`; write the n bytes of the input (UTF-8 JSON) at `p`.
2. `out = verify(p, n)`; then `free(p, n)`.
3. Read 4 bytes at `out` as a little-endian unsigned length `m`; the answer is the m bytes at `out + 4` (UTF-8 JSON).
4. `free(out, 4 + m)`.

The module is synchronous and keeps no state between calls other than its allocator. One instance serves one call at a time.

## Trap

`verify` traps instead of answering only on a bug or when memory is exhausted. After a trap the instance is discarded; the host instantiates a new one from the same compiled module before the next call. Hosts also replace an instance whose memory has grown past their limit.

## Input

A JSON object built by the host, at most 4 MiB:

```json
{ "op": "<operation>", "now": 1791747761, "evidence": "<the evidence as received, as a JSON string>", "trust": { … } }
```

Evidence, trust documents and registries are passed as JSON strings holding the bytes as received; the module reads them again with its strict reader. Which members an operation reads is listed with the operation.

## Answer

Canonical JSON (RFC 8785). Either `{"ok":true, …}` with what the module established, or `{"ok":false,"reason":"<reason>"}`. Hosts read results only from the answer, never by parsing the evidence themselves.

## Operations

FORMATS.md describes the documents.

| `op` | Reads | Answer when `ok` |
|---|---|---|
| `trust` | `trust` | `instance`, `sealer`, `issued_at`, `keys` (`kid`, `slot`, `alg`), `logs`, `verifiers`, `revoked`, `registries`, `dimensions` |
| `proof` | `envelope`, `proof`, `key` (JSON strings) | `origin`, `counter`, `alg`, `backup_eligible`, `backed_up` |
| `receipt` | `trust`, `evidence`, `expect` (optional; only `statement`, `aud`, `signer`) | `type`, `statement`, `envelope`, `dimension` (`digest`, `name`, `verifier`, `registry`, `signer`), `accepted` (`kid`, `at`), `anchor` (`log`, `index`), `key_record` (`log`, `index`, `at`, or null), and the `proof` answer |
| `app_receipt` | as `receipt`, and `holder_proof` (optional JSON string) | as `receipt`, without `key_record` and the `proof` answer |
| `ledger_note` | `trust`, `note` | `log`, `kid`, `body` (`kind` `receipt` with `origin`, `index`, `leaf_hash`; or `checkpoint` with `origin`, `size`, `root`, `time`) |
| `inclusion` | `index`, `size`, `leaf_hash`, `proof`, `root` | nothing more |
| `consistency` | `first`, `second`, `first_root`, `second_root`, `proof` | nothing more |
| `mandate_history` | `trust`, `grant` (a receipt string, holder or app), `terms`, `uses` (strings in `seq` order), `close` (string, optional) | `grant` (`type`, `mandate`, `app`, `request`, `on_behalf` or null), `terms`, `uses` (`seq`, `operation`, `at`, `totals`), `close` (`reason`, `at`, `uses`, or null) |
| `chain` | `trust`, `events` (skeleton strings in `seq` order), `from` (digest or null), `contents` (optional `{ seq, content }`), `snapshot` (optional string) | `actor`, `first`, `last`, `head`, `opened` (`seq`, `change`, `at`), `snapshot` (its `seq`, or null) |
| `bundle` | `trust`, `evidence` (a `ledger.bundle@1` string) | `log`, `index`, `committed_by`, `opening`, `anchor` (`anchored_by`, `tsa`, or null) |

`trust` is `{ "master": <JWK object>, "jwks": "<string>", "catalog": "<string>", "registries": ["<string>", …] }`. Hashes in `inclusion`, `consistency` and `ledger_note` are standard Base64 with padding, as in signed notes; a proof has at most 64 hashes.

## Hosts

The JavaScript and Go hosts do the same things, checked by the same conformance tests (`conformance/hosts-1.json`, built by `tools/genesis-vectors.mjs`; the small modules in `conformance/modules/` come from `tools/conformance-modules.mjs`).

- **Loading.** A host takes modules with their digests (`sha256:` + Base64URL of the bytes): it computes the digest when it has the bytes, and takes the declared one when a build step hands it a compiled module (Cloudflare Workers cannot compile at run time). The first module is the default. A host instantiates each module when it loads it and refuses the module (`unsupported_abi`) when an export is missing or `abi_version()` is not 1.
- **Instances.** After a trap the host discards the instance and answers `{"ok":false,"reason":"verifier_trap"}`. After a call, it discards an instance whose memory is above its limit (64 MiB unless set). It instantiates again only at the next call that needs it.
- **Which module runs.** Only modules the catalog lists in `verifiers` and does not revoke (genesis.md §18.4). To read the catalog the host first calls `trust` on the default module, and again on the first runnable module when the catalog revokes the default. Calls without `trust` run on the default module.
- **Receipts.** For `receipt` and `app_receipt`, the host follows the dimension's `verifier` through `revoked[].successor` and answers from that module, running it when it is not the one that answered first. It adds `"verifier": "<digest>"` to the answer. When it does not hold that module, it answers `verifier_unavailable`.
- **Freshness.** When `now` (the input's, or the clock's when the input has none) is more than 7 days after the catalog's `issued_at`, the host adds `"catalog_stale": true` to an `ok` answer of a call that read `trust`.

Host reasons, added to the module's:

| Reason | |
|---|---|
| `verifier_trap` | The module trapped. |
| `verifier_unavailable` | No module the host holds may answer: none is in the catalog unrevoked, or the receipt names one the host does not hold. |

## Reasons

Reasons are only added, never renamed or reused.

| Reason | |
|---|---|
| `input_too_large` | The input is larger than 4 MiB. |
| `input_malformed` | The input is not a JSON object with a string `op`, or a member the operation reads is missing or of the wrong type. |
| `unknown_op` | No operation by that name. |
| `json_syntax` | A document is not UTF-8 or not one JSON value. |
| `json_duplicate_key` | A document repeats a key in an object. |
| `json_lone_surrogate` | A document has a `\u` escape that leaves a lone surrogate. |
| `json_non_finite` | A document has a number that reads as infinity. |
| `json_too_deep` | A document nests arrays and objects more than 64 deep. |
| `trust_master` | The Master key is not an EC P-256 public JWK. |
| `trust_nomination` | The sealer nomination does not have its shape or the Master did not sign it. |
| `trust_jwks` | The JWKS does not have its shape. |
| `trust_jwks_signature` | The sealer did not sign a JWKS key. |
| `trust_catalog` | The catalog does not have its shape. |
| `trust_catalog_signature` | The sealer did not sign the catalog. |
| `registry_missing` | No registry passed has the digest the dimension names. |
| `registry_shape` | The registry does not read. |
| `registry_not_in_catalog` | The catalog does not list the registry the dimension names. |
| `receipt_type` | The receipt is not of the type the operation reads. |
| `receipt_shape` | The receipt does not have its members. |
| `envelope_shape` | The envelope does not have its shape. |
| `dimension_shape` | The dimension definition does not have its shape. |
| `dimension_digest` | The envelope names another dimension definition. |
| `dimension_not_in_catalog` | The catalog does not list the dimension definition. |
| `statement_shape` | The statement does not match its registry rule. |
| `statement_digest` | The envelope names another statement. |
| `statement_not_in_dimension` | The dimension does not accept the statement type. |
| `suite_not_in_dimension` | The dimension does not accept the method. |
| `suite_unknown` | The module does not know the method. |
| `aud` | The envelope's `aud` is not the one the registry template gives. |
| `extension_required` | An extension the dimension requires is missing. |
| `extension_not_allowed` | The envelope has an extension the dimension does not allow. |
| `extension_unknown` | `crit` names an extension the module does not know. |
| `receipt_kind` | The dimension does not issue receipts of this kind. |
| `expect_statement` | The statement type is not the expected one. |
| `expect_aud` | The `aud` is not the expected one. |
| `expect_signer` | The signer is not the expected one. |
| `holder_proof` | The holder proof passed is not the one the app receipt names. |
| `proof_shape` | The proof or the key does not have its shape. |
| `proof_credential` | The proof and the key name different credentials. |
| `proof_suite` | The envelope's method is not `webauthn@1`. |
| `proof_encoding` | A Base64URL member of the proof does not decode. |
| `proof_client_data` | `clientDataJSON` is not a JSON object. |
| `proof_client_data_type` | `clientDataJSON.type` is not `webauthn.get`. |
| `proof_challenge` | The challenge is not the envelope's. |
| `proof_cross_origin` | `clientDataJSON.crossOrigin` is true. |
| `proof_origin` | The origin is not https on the rp or below it. |
| `proof_authenticator_data` | The authenticator data is too short. |
| `proof_rp` | The rpIdHash is not the SHA-256 of the rp. |
| `proof_user_presence` | The user-present flag is not set. |
| `proof_user_verification` | The user-verified flag is not set. |
| `proof_public_key` | The key is not a COSE key the module reads. |
| `proof_signature` | The signature does not verify. |
| `proof_key_alg` | The COSE key's algorithm differs from the key's `alg`. |
| `attestation_shape` | `attestations` is not 1 to 8 objects with a type. |
| `accepted_shape` | An `accepted@1` does not have its shape. |
| `accepted_subject` | An `accepted@1` vouches for another core. |
| `accepted_key` | No `sign-receipt` key in the JWKS has the `accepted@1` kid. |
| `accepted_signature` | An `accepted@1` signature does not verify. |
| `accepted_missing` | No ES256 `accepted@1` is present. |
| `ledger_receipt_shape` | A `ledger.receipt@1` does not have its shape or does not hold a ledger receipt. |
| `ledger_receipt_log` | A `ledger.receipt@1` is from a log other than a first-party shard. |
| `ledger_receipt_leaf` | A `ledger.receipt@1` covers a leaf the receipt cannot compute. |
| `anchor_missing` | No `ledger.receipt@1` covers the receipt anchor. |
| `disclosure_shape` | `disclosures` is not 1 to 8 objects with a type. |
| `key_opening_shape` | A `key.opening@1` does not have its shape, or there are two. |
| `key_opening_binding` | The key record does not bind the receipt's key, rp or signer. |
| `key_opening_unanchored` | No `ledger.receipt@1` covers the key record. |
| `ledger_note_shape` | The note is not a ledger checkpoint or receipt. |
| `ledger_note_log` | The origin does not name a log the module reads. |
| `ledger_note_signer` | No key the catalog lists for the log signed the note. |
| `ledger_note_signature` | The note's signature does not verify. |
| `inclusion_proof` | The inclusion proof does not lead to the root. |
| `consistency_proof` | The consistency proof does not connect the roots. |
| `mandate_grant` | The grant receipt's statement is not a grant type the module reads. |
| `mandate_terms_shape` | The terms do not have their shape. |
| `mandate_terms_digest` | The grant names other terms. |
| `mandate_use_shape` | A use record does not have its shape. |
| `mandate_grant_digest` | A record names another grant. |
| `mandate_mismatch` | A record names another mandate. |
| `mandate_attest_signature` | No ES256 signature by a `mandate-attest` key verifies on a record. |
| `mandate_app_jwt_shape` | The app's JWT does not read. |
| `mandate_app_jwt_alg` | The JWT's `alg` does not match the app's key. |
| `mandate_app_jwt_signature` | The JWT's signature does not verify. |
| `mandate_app_jwt_app` | The JWT's `iss` or `app_id` is not the grant's app. |
| `mandate_app_jwt_aud` | The JWT's `aud` is not `clavis-ledger`. |
| `mandate_app_jwt_body` | The JWT's `body_sha256` is not the request's. |
| `mandate_app_jwt_time` | The JWT's `iat` and `exp` do not cover the use. |
| `mandate_before_grant` | A record is dated before the grant. |
| `mandate_totals` | A use's totals are not the ones the scope check gives. |
| `mandate_outside` | A use is outside the terms. |
| `mandate_use_chain` | A use does not follow the one before it. |
| `mandate_close_shape` | The close does not have its shape. |
| `mandate_close_reason` | `signer_designation_ended` closes a mandate not given in an organization's name. |
| `mandate_close_uses` | The close counts other uses than the records. |
| `mandate_close_expired` | An `expired` close is not dated at `not_after`. |
| `mandate_close_last` | The close does not name the last use. |
| `mandate_close_exhausted` | An `exhausted` close comes before the terms are used up. |
| `chain_shape` | A skeleton does not have its shape. |
| `chain_attest` | A skeleton or the snapshot is not signed by a `state-attest` key. |
| `chain_actor` | The skeletons belong to different actors. |
| `chain_link` | A skeleton does not follow the one before it (or `from`). |
| `chain_content_seq` | A content names a `seq` outside the skeletons given. |
| `chain_content_shape` | A content does not have its shape. |
| `chain_content_commit` | A content does not open its skeleton's `commit`. |
| `chain_snapshot_shape` | The snapshot does not have its shape or names another actor. |
| `chain_snapshot_head` | The snapshot's `head` is not the skeleton at its `seq`. |
| `bundle_shape` | The bundle does not have its shape. |
| `bundle_log` | The notes are from another log than the bundle's. |
| `bundle_receipt` | The ledger receipt is for another index or leaf. |
| `bundle_inclusion` | The inclusion proof does not lead to the checkpoint root. |
| `bundle_opening` | The opening does not give the leaf's commitment. |
| `bundle_anchor` | The anchor checkpoint is not the same host's `anchor` or does not include the checkpoint. |
