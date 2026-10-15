# Formats (draft)

The byte-level formats Collatio verifies from Clavis genesis on. Parts marked **Open** are proposals awaiting review; everything else follows decisions already made in the Clavis design. Formats that genesis does not change (RFC 8785, digests, the envelope challenge, `webauthn@1`, `shown@1`, key records, commitments, signed notes, leaves, Merkle proofs, TSA tokens) are implemented and described in the code.

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
| `aud` | The writer that consumes the signature: `<kind>:<id>` with kind `account`, `org`, `domain`, `document` or `request`; the whole value matches the ID characters and is ≤ 260 characters |
| `statement` | Digest of the statement (§2) |
| `signer` | ID (≤ 200) |
| `rp` | Lowercase domain, labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, ≤ 253 |
| `iat` | Unix seconds, ≥ 0 |
| `nonce` | 32 bytes, Base64URL |
| `ext` (optional) | Non-empty object; names are type IDs; known extensions (`shown@1`) are checked |
| `crit` (optional) | Non-empty sorted set of names present in `ext` |

The WebAuthn challenge is SHA-256(UTF-8(`suite`) ‖ 0x00 ‖ UTF-8(JCS(envelope))).

## 2. Statements and `registry@1`

A statement is `{ "type": "<type ID>", <fields> }`. Which fields a type has, their kinds and the `aud` template come from a registry document named by digest in the dimension:

```json
{ "type": "registry@1",
  "statements": {
    "app.sign@1": { "aud": "request:<request>", "fields": { "request": "id", "app": "app", "digest": "bytes32" } },
    "profile.patch@1": { "aud": "account:<signer>", "fields": { "display_name": "text(200)" } } } }
```

- Field names `[a-z][a-z0-9_]*`. A trailing `?` marks an optional field.
- The kind strings and their meaning are rules inside Collatio. The current kinds carry over unchanged: `id`, `uuid`, `app`, `subject`, `credential`, `digest`, `bytes32`, `hex64`, `domain`, `email`, `text(n)`, `int(min,max)`, `oneOf(a|b|…)`, `sortedSet(kind,max)`, `nullable(kind)`. New: `org`, an Org ID `<cell>.<UUID>` with the cell `[a-z]{2}[1-9][0-9]{0,2}`. A kind string must be in canonical form; an unknown or malformed one makes the whole registry unusable.
- The `aud` template is `[a-z0-9:._-]` text with `<field>` placeholders (as now). Each placeholder names a required field, or `signer` for the envelope's signer (new). The result must be a valid `aud` (§1).
- **Open:** field names `type` and `signer` are reserved, so `<signer>` never means a statement field. No current statement has a field named `signer`.
- A registry document only grows: a new document repeats every earlier type unchanged. Collatio reads only a document whose digest equals the dimension's `registry`.

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
- `attestations`: 1–8 objects; `disclosures` (holder only, optional): 1–8 objects. Each has a `type` that is a type ID. An attestation or disclosure of an unknown type is passed over unread; a known one that fails refuses the receipt. **Open:** the limit of 8.
- Required: at least one valid `accepted@1`, and a valid `ledger.receipt@1` for the receipt anchor.

### 4.1 `accepted@1`

```json
{ "type": "accepted@1", "subject": "sha256:…", "at": 1791747761, "kid": "clavis-sign-receipt-k7mq", "alg": "ES256", "sig": "…" }
```

- `subject` is the core digest; `at` is Unix seconds; `kid` names a key in the JWKS whose `${ns}-slot` is `sign-receipt`.
- `sig` is the ES256 signature as raw r‖s (64 bytes, Base64URL) over UTF-8(JCS(the attestation without `sig`)).
- **Open:** `alg` other than `ES256` (a post-quantum attestation) is skipped as unknown rather than refused, so a second attestation can be added later without failing old verifiers.

### 4.2 `ledger.receipt@1`

```json
{ "type": "ledger.receipt@1", "note": "clavis.ledger.receipt/v1\n<origin>\n<index>\n<leaf hash>\n\n— <kid> <signature>\n" }
```

- The note (≤ 4096 characters, as the current binding's receipt) is a signed note whose body is a ledger receipt. It verifies with the key the catalog lists for the log named in the origin (`<host>/ledger/<log id>`), and that key's slot is `ledger-log`.
- The log is a first-party shard (`first-party.<n>`) for the receipt anchor and for disclosed key records.
- The leaf hash must be one of the leaves computable from the receipt: the receipt anchor `{ v: 1, c }` with c = hex(SHA-256(UTF-8(JCS({ type: "receipt.anchor@1", envelope: digestOf(envelope), proof: digestOf(holder proof) })))) — the app receipt uses its `proof` digest — or a disclosed key record's commitment. A ledger receipt matching none of them refuses the receipt.

### 4.3 `key.opening@1`

```json
{ "type": "key.opening@1", "salt": "…", "record": { "type": "key.bound@1", … } }
```

- The commitment of `{salt, record}` (`clavis.commit.v1`) is a leaf covered by one of the receipt's `ledger.receipt@1`.
- The record binds the receipt's key: same `credential`, `public_key` and `alg`; same `rp` as the envelope; and, for `account` dimensions, the same `signer`.

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
- `ns` is `[a-z][a-z0-9]{1,31}` (`clavis`). **Open:** Collatio reads it from the field names, as the current reader does, and requires one `ns` across the document, rather than taking it from the caller.
- **Open:** the current keys also carry `x-${ns}-signature-version`, `-signature-purpose`, `-signature-alg`, `-key-slot` and `-key-generation`. The proposal drops all of them: version and purpose are fixed inside the signed payload, the algorithm is ES256, the slot moves to `${ns}-slot`, and genesis kids carry a thumbprint tag instead of a generation (so `generation` leaves the payload too).
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

- **Open:** `issued_at` as Unix seconds (the design sketch shows a date string; Clavis types use integers).
- **Open:** the signature as a `signature` member over UTF-8(JCS(catalog without `signature`)), with `kid` equal to the nominated sealer's kid.

## 6. Operations

Inputs follow ABI.md. As in the design (§18.3), the caller builds the outside and passes evidence, trust documents and registries as the JSON strings it received: `{ "op": "receipt", "now": …, "expect": { … }, "trust": { "master": { …JWK… }, "jwks": "<string>", "catalog": "<string>", "registries": ["<string>"] }, "evidence": "<string>" }`.

| `op` | Input | Answer (when `ok`) |
|---|---|---|
| `trust` | `trust` | the nominated sealer, keys by slot, logs, verifiers, registries, dimensions |
| `proof` | `envelope`, `proof`, `key` | origin, counter, algorithm (used at ceremony completion) |
| `receipt` | `trust`, `evidence`, `expect` (statement type, `aud`, `signer`) | statement, envelope, signer, attestations checked, key binding result |
| `app_receipt` | as `receipt`, optional `holder_proof` | as `receipt` |
| `ledger_note` | `trust`, `note` | the body and its parsed checkpoint or receipt |
| `inclusion` | `index`, `size`, `leaf`, `proof`, `root` | — |
| `consistency` | `first`, `second`, `first_root`, `second_root`, `proof` | — |
| `bundle` | `trust`, `evidence` (ledger evidence bundle) | `committed_by`, opening checked, anchor with TSA count |
| `mandate_history`, `chain` | — | defined with the delegation records and event chains (next draft) |

Not in this draft: delegation records (`mandate.*@1`), event chains (`event@1`, `event.content@1`, `state.snapshot@1`, `state.head@1`, `state.heads@1`), and the genesis form of the ledger evidence bundle.
