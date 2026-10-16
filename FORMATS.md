# Formats

The byte-level formats Collatio verifies from Clavis genesis on. They follow the Clavis design (genesis.md); the points this document settled beyond it were confirmed on 2026-10-15. Formats that genesis does not change (RFC 8785, digests, the envelope challenge, `webauthn@1`, `shown@1`, key records, commitments, signed notes, leaves, Merkle proofs, TSA tokens) are implemented and described in the code.

## 0. Conventions

- **Reading.** Every Clavis document is read by the strict reader: UTF-8, unique keys, no lone surrogates, depth ≤ 64. Clavis types hold numbers only as integers within ±(2^53 − 1), written without fraction or exponent. App records inside bundles are arbitrary JSON and keep RFC 8785 numbers.
- **Canonical form.** RFC 8785. The digest of a value is `sha256:` + Base64URL(SHA-256(UTF-8(JCS(value)))).
- **Type IDs.** `<name>@<version>`: dot-separated parts of `[a-z][a-z0-9_]*`, version ≥ 1 without leading zeros, ≤ 128 characters. A shape that changes gets a new version; a version is never reused.
- **IDs.** `[A-Za-z0-9._~:@+=/-]{1,200}` unless stated.
- **Base64URL** is unpadded and canonical (unused trailing bits are zero). Signed notes and checkpoints use standard Base64 with padding (C2SP).
- **Sorted sets.** Arrays described as sets are strictly increasing by UTF-16 code units (no duplicates).
- **Members.** A document has exactly the members listed; optional ones are marked. Unknown members are refused, except where a section says otherwise.

## 1. Envelope

Unchanged from the current design except `aud`.

| Member | |
|---|---|
| `suite` | Type ID of the method (`webauthn@1`) |
| `dimension` | Digest of the dimension definition (§3) |
| `aud` | The writer that consumes the signature: `<writer>:<id>`, ≤ 260 characters of the ID set (see below) |
| `statement` | Digest of the statement (§2) |
| `signer` | ID (≤ 200) |
| `rp` | Lowercase domain, labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, ≤ 253 |
| `iat` | Unix seconds, ≥ 0 |
| `nonce` | 32 bytes, Base64URL |
| `ext` (optional) | Non-empty object; names are type IDs; known extensions (`shown@1`) are checked |
| `crit` (optional) | Non-empty sorted set of names present in `ext` |

The WebAuthn challenge is SHA-256(UTF-8(`suite`) ‖ 0x00 ‖ UTF-8(JCS(envelope))).

- The writers at genesis are `account`, `org`, `domain`, `document` and `request` (genesis.md §5.2). They are named by the registry's templates, not listed in Collatio: the envelope only requires `<writer>` to be `[a-z][a-z0-9_]{0,31}` and something after the colon. So a new writer is a registry change, not a module release.
- An extension Collatio knows (`shown@1`) is checked whether or not `crit` names it. An unknown one is not read; when `crit` names it, the receipt is refused (`extension_unknown`).

## 2. Statements and `registry@1`

A statement is `{ "type": "<type ID>", <fields> }`. Which fields a type has, their kinds and the `aud` template come from a registry document named by digest in the dimension:

```json
{ "type": "registry@1",
  "statements": {
    "app.sign@1": { "aud": "request:<request>", "fields": { "request": "id", "app": "app", "digest": "bytes32" } },
    "profile.patch@1": { "aud": "account:<signer>", "fields": { "display_name": "text(200)" } } } }
```

- Field names `[a-z][a-z0-9_]*`. A trailing `?` marks an optional field.
- The kind strings and their meaning are rules inside Collatio. The current kinds carry over unchanged: `id`, `uuid`, `app`, `subject`, `credential`, `digest`, `bytes32`, `hex64`, `domain`, `email`, `text(n)`, `int(min,max)`, `oneOf(a|b|…)`, `sortedSet(kind,max)`, `nullable(kind)`. New: `org`, an Org ID `<cell>.<UUID>` with the cell `[a-z]{2}[1-9][0-9]{0,2}`. A kind string must be in canonical form; an unknown or malformed one makes the whole registry unusable. Two readings are stricter than before (§0): `bytes32` must be canonical Base64URL, and `int(…)` values must be written as integers. `credential` stays as before (Base64URL characters, any length that can be Base64URL, ≤ 1366).
- The `aud` template is `[a-z0-9:._-]` text with `<field>` placeholders (as now). It starts with the literal `<writer>:`. Each placeholder names a required field, or `signer` for the envelope's signer (new). The result must be a valid `aud` (§1).
- Field names `type` and `signer` are reserved, so `<signer>` never means a statement field. No current statement has a field named `signer`.
- A registry document only grows: a new document repeats every earlier type unchanged. Collatio reads only a document whose digest equals the dimension's `registry`, and only when the catalog lists that digest in `registries` and the dimension's digest in `dimensions`.

## 3. `dimension@1`

The current definition plus `verifier` and `registry`; 14 members:

| Member | |
|---|---|
| `type` | `dimension@1` |
| `name` | `[a-z][a-z0-9_]{0,63}` |
| `statements` | Non-empty sorted set of type IDs |
| `suites` | Non-empty sorted set of type IDs |
| `verifier` | Digest of the Collatio module that verifies this dimension's receipts |
| `registry` | Digest of the `registry@1` document for its statements |
| `signer` | `account` or `pairwise` |
| `sessions` | Non-empty sorted subset of `app`, `portal` |
| `rp` | `platform` |
| `freshness` | Seconds (> 0) or `null` |
| `single_use` | Boolean |
| `ext` | `{ "required": set, "allowed": set }`, required ⊆ allowed |
| `receipts` | Non-empty sorted subset of `app`, `holder` |
| `key_log` | Boolean |

## 4. Receipts

```jsonc
{ "type": "receipt@1",                 // holder receipt
  "statement": { … }, "envelope": { … }, "proof": { … }, "key": { … }, "dimension": { … },
  "attestations": [ … ], "disclosures": [ … ] }

{ "type": "receipt.app@1",             // app receipt: the proof as a digest, no key, no disclosures
  "statement": { … }, "envelope": { … }, "proof": "sha256:…", "dimension": { … },
  "attestations": [ … ] }
```

- **Core**: every member except `attestations` and `disclosures`. The subject of an attestation is `digestOf(core)`.
- `attestations`: 1–8 objects; `disclosures` (holder only, optional): 1–8 objects. Each has a `type` that is a type ID. An attestation or disclosure of an unknown type is passed over unread; a known one that fails refuses the receipt.
- Order of checks, so a receipt gets one reason: shape, envelope, dimension (digest, catalog), registry, statement, `aud`, extensions, receipt kind, the caller's expectations, the proof, disclosures, attestations.
- Required: at least one valid `accepted@1`, and a valid `ledger.receipt@1` for the receipt anchor.

### 4.1 `accepted@1`

```json
{ "type": "accepted@1", "subject": "sha256:…", "at": 1791747761, "kid": "clavis-sign-receipt-k7mq", "alg": "ES256", "sig": "…" }
```

- `subject` is the core digest; `at` is Unix seconds; `kid` names a key in the JWKS whose `${ns}-slot` is `sign-receipt`.
- `sig` is the ES256 signature as raw r‖s (64 bytes, Base64URL) over UTF-8(JCS(the attestation without `sig`)).
- An `accepted@1` with an `alg` other than `ES256` (a post-quantum attestation) is skipped as unknown rather than refused, so a second attestation can be added later without failing old verifiers. It must still have the six members, a digest `subject` and an integer `at`.

### 4.2 `ledger.receipt@1`

```json
{ "type": "ledger.receipt@1", "note": "clavis.ledger.receipt/v1\n<origin>\n<index>\n<leaf hash>\n\n— <kid> <signature>\n" }
```

- The note (≤ 4096 characters, as the current binding's receipt) is a signed note whose body is a ledger receipt. It verifies with the key the catalog lists for the log named in the origin (`<host>/ledger/<log id>`), and that key's slot is `ledger-log`. The signature line's name is the kid.
- Collatio checks that `<host>` is a lowercase host but does not tie it to the instance; the caller sees the origin in the `ledger_note` answer.
- The log is a first-party shard (`first-party.<n>`) for the receipt anchor and for disclosed key records.
- The leaf hash must be one of the leaves computable from the receipt: the receipt anchor `{ v: 1, c }` with c = hex(SHA-256(UTF-8(JCS({ type: "receipt.anchor@1", envelope: digestOf(envelope), proof: digestOf(holder proof) })))) — the app receipt uses its `proof` digest — or a disclosed key record's commitment. A ledger receipt matching none of them refuses the receipt.

### 4.3 `key.opening@1`

```json
{ "type": "key.opening@1", "salt": "…", "record": { "type": "key.bound@1", … } }
```

- The commitment of `{salt, record}` (`clavis.commit.v1`) is a leaf covered by one of the receipt's `ledger.receipt@1`.
- The record binds the receipt's key: same `credential`, `public_key` and `alg`; same `rp` as the envelope; and, for `account` dimensions, the same `signer`.
- At most one `key.opening@1` per receipt (a receipt has one key).

## 5. Trust

The only trust root a caller passes is the Master public key (P-256 JWK).

### 5.1 Sealer nomination

The current `platform.sealer.nominate` document, signed by the Master:

```jsonc
{ "payload": { "v": 1, "purpose": "platform.sealer.nominate", "instance_id": "clavis.nexus", "sealer_kid": "…",
               "sealer_public_jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…", "alg": "ES256" }, "iat": 1791747761 },
  "signature": "…" }            // ES256 raw r‖s over UTF-8(JCS(payload))
```

### 5.2 Aggregated JWKS

```jsonc
{ "keys": [ { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "clavis-sign-receipt-k7mq", "alg": "ES256",
              "clavis-slot": "sign-receipt", "clavis-sealer-signature": "…" } ],
  "sealer": { …nomination… } }
```

- Each key carries its slot in `${ns}-slot` and the sealer's signature in `${ns}-sealer-signature` (one signature per key, as now): ES256 raw r‖s over UTF-8(JCS({ "version": 1, "purpose": "signed-jwks-child", "protocol_ns": ns, "slot": slot, "public_jwk": { kty, crv, x, y (null for OKP), kid, alg } })).
- `ns` is `[a-z][a-z0-9]{1,31}` (`clavis`). Collatio reads it from the field names, as the pre-genesis reader does, and requires one `ns` across the document.
- The pre-genesis keys also carry `x-${ns}-signature-version`, `-signature-purpose`, `-signature-alg`, `-key-slot` and `-key-generation`. Genesis drops all of them: version and purpose are fixed inside the signed payload, the algorithm is ES256, the slot moves to `${ns}-slot`, and kids carry a thumbprint tag instead of a generation (so `generation` leaves the payload too).
- A key has exactly `kty`, `crv`, `x`, `y` (EC only), `kid`, `alg`, `${ns}-slot` and `${ns}-sealer-signature`; P-256 keys are `ES256`, Ed25519 keys are `OKP`/`EdDSA`. Unknown top-level members are not read (so members can be added later).

### 5.3 `catalog@1`

As in the design (§10.1), signed by the sealer:

```jsonc
{ "type": "catalog@1", "issued_at": 1791747761, "sealer": { …nomination… },
  "verifiers": [ { "digest": "sha256:…", "source": { "repo": "https://github.com/clavisnexus/collatio", "tag": "v1.0.0", "commit": "…" } } ],
  "revoked": [ { "verifier": "sha256:…", "reason": "…", "successor": "sha256:…" } ],
  "registries": [ "sha256:…" ], "dimensions": [ "sha256:…" ],
  "logs": [ { "id": "first-party.0", "kid": "clavis-ledger-log-c2vw" }, { "id": "anchor", "kid": "clavis-ledger-log-8wqa" } ],
  "signature": { "kid": "…", "alg": "ES256", "sig": "…" } }
```

- `verifiers`: at least one, digests unique; `source.repo` is an `https://` URL, `tag` printable ASCII, `commit` 40 or 64 lowercase hex. `revoked`: each `verifier` and `successor` is a listed verifier, they differ, and a verifier is revoked once; `reason` is trimmed text ≤ 500. `registries`, `dimensions`: digests without duplicates, in the order they were added. `logs`: `first-party.<n>` or `anchor`; a log appears once per kid, so twice while its key rotates.
- `issued_at` is Unix seconds (Clavis types hold integers).
- The signature is the `signature` member, over UTF-8(JCS(catalog without `signature`)), with `kid` equal to the nominated sealer's kid.

## 6. Operations

ABI.md lists the operations, what each reads and answers, and the reasons. As in the design (§18.3), the caller builds the outside and passes evidence, trust documents and registries as the JSON strings it received: `{ "op": "receipt", "now": …, "expect": { … }, "trust": { "master": { …JWK… }, "jwks": "<string>", "catalog": "<string>", "registries": ["<string>"] }, "evidence": "<string>" }`.

## 7. Delegation records

The records keep their pre-genesis shapes (`mandate.terms@1`, `mandate.use_request@1`, `mandate.use@1`) and rules (the scope check, totals, the chain of uses). What changes:

- `mandate.close@1` takes the reasons `account_closed`, `exhausted`, `expired`, `revoked_by_app`, `revoked_by_holder` and `signer_designation_ended`. The last is allowed only when the grant is `mandate.grant.on_behalf@1`. `mandate.close@2` is gone (genesis.md §5.5).
- The grant is a receipt (holder or app) whose statement is a grant type. Grant types are rules of the module:

| Grant | Reads | |
|---|---|---|
| `mandate.grant@1` | `request`, `app`, `mandate` (UUID), `terms` (digest) | |
| `mandate.grant.on_behalf@1` | the same, and `org` (Org ID), `domain` | in the name of an organization |

- Clavis's signature stays in `sigs` (1–4 of `{ kid, alg, sig }`): ES256 raw r‖s over UTF-8(JCS(record without `sigs`)), by a JWKS key in slot `mandate-attest`. A signature with another `alg` is not read; at least one ES256 one must verify. A record's digest is `digestOf(record without sigs)`.
- The app's JWT (`app.jwt`, compact JWS) is checked as before: `EdDSA` with an OKP key or `ES256` with an EC key; `iss` = `app:<app>`, `app_id` = `<app>`, `aud` = `clavis-ledger`, `body_sha256` = hex(SHA-256(UTF-8(JCS(request)))), and `iat` − 30 ≤ `at` ≤ `exp` + 30. The header and payload are read by the strict reader (a repeated key is refused) and `iat`, `exp` must be integers; the pre-genesis reader took any JSON number and let a repeated key win.
- The first use's totals must start from nothing. The pre-genesis check compared totals only with the use before, so a first use could claim an amount already spent; Collatio refuses it (`mandate_totals`).
- The `mandate_history` operation reads `trust`, `grant` (the receipt string), `terms` (string), `uses` (strings in `seq` order) and `close` (string, optional). It checks the grant receipt fully (§4), then the terms against the grant's `terms`, then each use against the one before, then the close against the last use.
- The `mandate_record` operation reads `trust` and one `record` (a use or a close), and `app` (optional). It checks the record's shape, Clavis's signature and, for a use with `app`, the app's JWT, and answers the record's members (a use's request as its digest). It does not check the chain or the scope, which need the grant and the other records; an app reads a use this way right after making it and checks the whole history with `mandate_history`.

## 8. Event chains

Account and Org state are chains of skeletons (genesis.md §19.2). A skeleton links and commits; the content is kept apart and may be deleted.

```jsonc
{ "type": "event@1", "actor": "eu1.Q2xh…", "seq": 42, "prev": "sha256:…", "commit": "sha256:…",
  "envelope": "sha256:…", "leaves": ["<c>"], "attest": { "kid": "clavis-state-attest-9hd4", "alg": "EdDSA", "sig": "…" } }
```

- `actor`: an account ID (`<cell>.<43 Base64URL characters>`) or an Org ID (`<cell>.<UUID>`). `seq` ≥ 1; `prev` is null exactly when `seq` is 1. `envelope` is the envelope digest when a receipt caused the change, else null. `leaves`: 0–16 leaf `c` values, without duplicates.
- `attest`: Ed25519 over UTF-8(JCS(skeleton without `attest`)) by a JWKS key in slot `state-attest`. The skeleton's digest is `digestOf(skeleton without attest)`; the next skeleton's `prev` is that digest. `alg` is `EdDSA`, the JOSE name the JWKS key carries.
- Content (`event.content@1`), kept by the writer as `{ salt, change, at, payload, receipt }`: `salt` 32 bytes Base64URL; `change` a type ID; `at` Unix seconds; `payload` an object; `receipt` the holder receipt string when the signer's receipt caused the change, else null. `commit` = `sha256:` + Base64URL(SHA-256(UTF-8(`clavis.event.v1`) ‖ salt ‖ UTF-8(JCS({ type: "event.content@1", change, at, payload, receipt })))).
- Snapshot (`state.snapshot@1`): `{ type, actor, seq, head, state, attest }`: the state after event `seq`, whose skeleton digest is `head`, signed like a skeleton.
- Head leaf (`state.head@1`): c = hex(SHA-256(UTF-8(`clavis.commit.v1`) ‖ salt ‖ UTF-8(JCS({ type: "state.head@1", seq, head })))). The aggregated head (`state.heads@1`) is specified when aggregation is built (genesis.md §19.4: when leaves grow).
- The `chain` operation reads `trust`, `events` (skeleton strings in `seq` order), `from` (the digest before the first skeleton, or null when it starts at 1), `contents` (optional `{ seq, content }` with content strings) and `snapshot` (optional string). It checks every signature and link, opens the contents given, and checks the snapshot against the skeleton at its `seq`.

## 9. Ledger evidence bundle (`ledger.bundle@1`)

The pre-genesis bundle v1 without its JWKS copy, since trust comes from `trust`:

```jsonc
{ "type": "ledger.bundle@1", "log": "<log ID>", "leaf": { "v": 1, "c": "…" }, "index": 7,
  "receipt": "<note>", "checkpoint": "<note>", "inclusion": ["<base64>", …],
  "opening": { "salt": "…", "record": { … } },                                        // optional
  "anchor": { "index": 3, "checkpoint": "<note>", "inclusion": [ … ], "tsa": [ { "response": "<base64 DER>" } ] } }   // optional
```

- `log`: a first-party shard or an Org ID (the Org's log). Notes of first-party shards and `anchor` verify with the keys the catalog lists; notes of an Org's log verify with any JWKS key in slot `ledger-log`, as now, because the catalog does not list Org logs.
- The receipt and the checkpoint have the origin `<host>/ledger/<log>`; the receipt's index and leaf hash are the bundle's; the inclusion proof leads from the leaf to the checkpoint root.
- `opening`: the commitment of `{ salt, record }` (`clavis.commit.v1`) is the leaf's `c`. The record is the app's JSON (RFC 8785 numbers; repeated keys refused).
- `anchor`: the anchor leaf `{ v: 1, c: hex(SHA-256(UTF-8(checkpoint body))) }` is in the anchor checkpoint (origin `<same host>/ledger/anchor`), and each TSA token stamps the anchor checkpoint body. A token counts when it verifies against the TSA registry at its genTime; tokens that do not verify are not counted (as now).
- The `bundle` operation answers `committed_by` (the checkpoint time), `opening` (true when given and matching) and `anchor` (`anchored_by`, `tsa` count) or null.
