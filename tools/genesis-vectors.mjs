#!/usr/bin/env node
// Writes vectors/genesis/ops-1.json: calls to the module with the answers FORMATS.md requires.
//
// This is a second, independent implementation of the issuing side (node:crypto only): it signs
// passkey proofs, JWKS keys, the sealer nomination, the catalog, `accepted@1` attestations and
// ledger notes, and states the expected answer of each call. Keys come from fixed seeds; ECDSA
// signatures are randomized, so a rerun changes the signature bytes but not the answers.
//
//   node tools/genesis-vectors.mjs

import { createECDH, createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------- encoding

/** RFC 8785 for the values these vectors hold (strings, safe integers, booleans, null). */
function jcs(v) {
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (v !== null && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`)
      .join(",")}}`;
  }
  if (typeof v === "number" && !Number.isSafeInteger(v)) throw new Error(`not an integer: ${v}`);
  return JSON.stringify(v);
}

/** RFC 8785 for app records, whose numbers may have fractions (ECMAScript number form). */
function jcsAny(v) {
  if (Array.isArray(v)) return `[${v.map(jcsAny).join(",")}]`;
  if (v !== null && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcsAny(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

const sha256 = (b) => createHash("sha256").update(b).digest();
const b64u = (b) => Buffer.from(b).toString("base64url");
const b64 = (b) => Buffer.from(b).toString("base64");
const hex = (b) => Buffer.from(b).toString("hex");
const digestOf = (v) => `sha256:${b64u(sha256(jcs(v)))}`;
const clone = (v) => JSON.parse(JSON.stringify(v));

/** Deterministic bytes for a label. */
const bytes = (label, n = 32) => sha256(`collatio.vectors/${label}`).subarray(0, n);

// ---------------------------------------------------------------- keys

function p256(label) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(bytes(`p256/${label}`));
  const pub = ecdh.getPublicKey(null, "uncompressed");
  const x = b64u(pub.subarray(1, 33));
  const y = b64u(pub.subarray(33, 65));
  const priv = createPrivateKey({
    key: { kty: "EC", crv: "P-256", x, y, d: b64u(ecdh.getPrivateKey()) },
    format: "jwk",
  });
  return { priv, x, y, xBytes: pub.subarray(1, 33), yBytes: pub.subarray(33, 65) };
}

function ed25519(label) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), bytes(`ed25519/${label}`)]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x;
  return { priv, x, raw: Buffer.from(x, "base64url") };
}

/** ES256, raw r‖s, Base64URL. */
const es256 = (key, text) => b64u(sign("sha256", Buffer.from(text), { key: key.priv, dsaEncoding: "ieee-p1363" }));

function base32(buf) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

/** `${ns}-${slot}-${tag}`, the tag being the first 4 Base32 characters of the RFC 7638 thumbprint. */
function kidFor(slot, jwk) {
  const members = jwk.kty === "EC" ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return `clavis-${slot}-${base32(sha256(jcs(members))).slice(0, 4)}`;
}

const ecJwk = (k) => ({ kty: "EC", crv: "P-256", x: k.x, y: k.y });
const okpJwk = (k) => ({ kty: "OKP", crv: "Ed25519", x: k.x });

// ---------------------------------------------------------------- trust

const NS = "clavis";
const HOST = "clavis.nexus";
const master = p256("master");
const otherMaster = p256("other-master");
const sealer = p256("sealer");
const signReceipt = p256("sign-receipt");
const ledgerFp0 = ed25519("ledger-first-party-0");
const ledgerAnchor = ed25519("ledger-anchor");
const ledgerStray = ed25519("ledger-stray");
const passkey = p256("passkey");
const mandateAttest = p256("mandate-attest");
const stateAttest = ed25519("state-attest");
const appOperate = ed25519("app-operate");

const SEALER_KID = "clavis-sealer";
const IAT = 1791747761;

function nominate(by, sealerKey, sealerKid) {
  const payload = {
    v: 1,
    purpose: "platform.sealer.nominate",
    instance_id: HOST,
    sealer_kid: sealerKid,
    sealer_public_jwk: { ...ecJwk(sealerKey), kid: sealerKid, alg: "ES256" },
    iat: 1791699505,
  };
  return { payload, signature: es256(by, jcs(payload)) };
}

const nomination = nominate(master, sealer, SEALER_KID);

function jwksKey(slot, key, alg, by = sealer) {
  const jwk = alg === "ES256" ? ecJwk(key) : okpJwk(key);
  const kid = kidFor(slot, jwk);
  const pub = { ...jwk, kid, alg };
  const payload = {
    version: 1,
    purpose: "signed-jwks-child",
    protocol_ns: NS,
    slot,
    public_jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y ?? null, kid, alg },
  };
  return { ...pub, [`${NS}-slot`]: slot, [`${NS}-sealer-signature`]: es256(by, jcs(payload)) };
}

const KEYS = {
  signReceipt: jwksKey("sign-receipt", signReceipt, "ES256"),
  fp0: jwksKey("ledger-log", ledgerFp0, "EdDSA"),
  anchor: jwksKey("ledger-log", ledgerAnchor, "EdDSA"),
  stray: jwksKey("ledger-log", ledgerStray, "EdDSA"),
  mandateAttest: jwksKey("mandate-attest", mandateAttest, "ES256"),
  stateAttest: jwksKey("state-attest", stateAttest, "EdDSA"),
};
const jwks = { keys: Object.values(KEYS), sealer: nomination };

const registry = {
  type: "registry@1",
  statements: {
    "profile.patch@1": { aud: "account:<signer>", fields: { display_name: "text(200)" } },
    "app.sign@1": { aud: "request:<request>", fields: { request: "id", app: "app", digest: "bytes32" } },
    "mandate.grant@1": { aud: "request:<request>", fields: { request: "id", app: "app", mandate: "uuid", terms: "digest" } },
    "mandate.grant.on_behalf@1": {
      aud: "request:<request>",
      fields: { request: "id", app: "app", mandate: "uuid", terms: "digest", org: "org", domain: "domain" },
    },
  },
};
const VERIFIER = `sha256:${b64u(sha256("collatio test module"))}`;

const accountDim = {
  type: "dimension@1",
  name: "account",
  statements: ["profile.patch@1"],
  suites: ["webauthn@1"],
  verifier: VERIFIER,
  registry: digestOf(registry),
  signer: "account",
  sessions: ["portal"],
  rp: "platform",
  freshness: 300,
  single_use: true,
  ext: { required: [], allowed: [] },
  receipts: ["holder"],
  key_log: true,
};
const appDim = {
  ...accountDim,
  name: "app_sign",
  statements: ["app.sign@1"],
  signer: "pairwise",
  sessions: ["app"],
  ext: { required: ["shown@1"], allowed: ["shown@1"] },
  receipts: ["app", "holder"],
};

const mandateDim = {
  ...accountDim,
  name: "mandate",
  statements: ["mandate.grant.on_behalf@1", "mandate.grant@1"],
  signer: "pairwise",
  sessions: ["app"],
  receipts: ["app", "holder"],
};

function signCatalog(body, by = sealer) {
  return { ...body, signature: { kid: SEALER_KID, alg: "ES256", sig: es256(by, jcs(body)) } };
}

const catalogBody = {
  type: "catalog@1",
  issued_at: 1791750000,
  sealer: nomination,
  verifiers: [{ digest: VERIFIER, source: { repo: "https://github.com/clavisnexus/collatio", tag: "v1.0.0", commit: "a".repeat(40) } }],
  revoked: [],
  registries: [digestOf(registry)],
  dimensions: [digestOf(accountDim), digestOf(appDim), digestOf(mandateDim)],
  logs: [
    { id: "first-party.0", kid: KEYS.fp0.kid },
    { id: "anchor", kid: KEYS.anchor.kid },
  ],
};
const catalog = signCatalog(catalogBody);

const trust = (over = {}) => ({
  master: { ...ecJwk(master), kid: "clavis-master", alg: "ES256" },
  jwks: JSON.stringify(over.jwks ?? jwks),
  catalog: JSON.stringify(over.catalog ?? catalog),
  registries: (over.registries ?? [registry]).map((r) => JSON.stringify(r)),
  ...(over.master ? { master: over.master } : {}),
});

// ---------------------------------------------------------------- ledger

function note(body, key, kid) {
  const keyHash = sha256(Buffer.concat([Buffer.from(`${kid}\n`), Buffer.from([0x01]), key.raw])).subarray(0, 4);
  const sig = sign(null, Buffer.from(body), key.priv);
  return `${body}\n— ${kid} ${b64(Buffer.concat([keyHash, sig]))}\n`;
}

const leafHash = (c) => sha256(Buffer.concat([Buffer.from([0]), Buffer.from(jcs({ v: 1, c }))]));

/** Where the answer says a ledger receipt places leaf `c` (ABI.md: `anchor`, `key_record`). */
const placeOf = (c, index, log = "first-party.0") => ({ log, index, origin: `${HOST}/ledger/${log}`, leaf_hash: b64(leafHash(c)) });

function ledgerReceipt(c, index, { log = "first-party.0", key = ledgerFp0, kid = KEYS.fp0.kid } = {}) {
  const body = `clavis.ledger.receipt/v1\n${HOST}/ledger/${log}\n${index}\n${b64(leafHash(c))}\n`;
  return { type: "ledger.receipt@1", note: note(body, key, kid) };
}

// ---------------------------------------------------------------- passkey

const CREDENTIAL = b64u(bytes("credential", 16));
const coseKey = Buffer.concat([
  Buffer.from("a5010203262001215820", "hex"),
  passkey.xBytes,
  Buffer.from("225820", "hex"),
  passkey.yBytes,
]);
const KEY = { credential: CREDENTIAL, public_key: b64u(coseKey), alg: -7 };

function challenge(envelope) {
  return sha256(Buffer.concat([Buffer.from(envelope.suite), Buffer.from([0]), Buffer.from(jcs(envelope))]));
}

function prove(envelope, { counter = 7, origin = `https://${HOST}` } = {}) {
  const clientData = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: b64u(challenge(envelope)), origin, crossOrigin: false }),
  );
  const counterBytes = Buffer.alloc(4);
  counterBytes.writeUInt32BE(counter);
  const authData = Buffer.concat([sha256(envelope.rp), Buffer.from([0x05]), counterBytes]);
  const signature = sign("sha256", Buffer.concat([authData, sha256(clientData)]), passkey.priv);
  return {
    credential: CREDENTIAL,
    authenticator_data: b64u(authData),
    client_data_json: b64u(clientData),
    signature: b64u(signature),
  };
}

// ---------------------------------------------------------------- receipts

const SIGNER = `eu1.${b64u(bytes("account"))}`;
const PAIRWISE = `p_${b64u(bytes("pairwise", 18))}`;
const REQUEST = `eu1.${b64u(bytes("request", 18))}`;
const APP = "0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10";

function envelopeFor(statement, dimension, signer, aud, extra = {}) {
  return {
    suite: "webauthn@1",
    dimension: digestOf(dimension),
    aud,
    statement: digestOf(statement),
    signer,
    rp: HOST,
    iat: IAT,
    nonce: b64u(bytes(`nonce/${aud}`)),
    ...extra,
  };
}

function accepted(core, { key = signReceipt, kid = KEYS.signReceipt.kid, at = IAT + 1, alg = "ES256" } = {}) {
  const a = { type: "accepted@1", subject: digestOf(core), at, kid, alg };
  return { ...a, sig: es256(key, jcs(a)) };
}

const anchorC = (envelope, proofDigest) =>
  hex(sha256(jcs({ type: "receipt.anchor@1", envelope: digestOf(envelope), proof: proofDigest })));

// Account dimension, holder receipt.
const accountStatement = { type: "profile.patch@1", display_name: "Hamachi" };
const accountEnvelope = envelopeFor(accountStatement, accountDim, SIGNER, `account:${SIGNER}`);
const accountProof = prove(accountEnvelope);
const accountCore = {
  type: "receipt@1",
  statement: accountStatement,
  envelope: accountEnvelope,
  proof: accountProof,
  key: KEY,
  dimension: accountDim,
};
const accountAnchor = anchorC(accountEnvelope, digestOf(accountProof));
const holder = {
  ...accountCore,
  attestations: [accepted(accountCore), ledgerReceipt(accountAnchor, 41)],
};

// The key record and its opening.
const keyRecord = {
  type: "key.bound@1",
  signer: SIGNER,
  credential: CREDENTIAL,
  public_key: KEY.public_key,
  alg: -7,
  rp: HOST,
  at: IAT - 86400,
  by: "registration",
};
const salt = bytes("salt");
const openingC = (record, s = salt) =>
  hex(sha256(Buffer.concat([Buffer.from("clavis.commit.v1"), s, Buffer.from(jcs(record))])));
const opening = { type: "key.opening@1", salt: b64u(salt), record: keyRecord };
const holderDisclosed = {
  ...accountCore,
  attestations: [accepted(accountCore), ledgerReceipt(accountAnchor, 41), ledgerReceipt(openingC(keyRecord), 3)],
  disclosures: [opening],
};

// App dimension: holder and app receipts of one signature.
const appStatement = { type: "app.sign@1", request: REQUEST, app: APP, digest: b64u(bytes("document")) };
const shown = { app: "Acme", host: "acme.example", action: "Sign the contract" };
const appEnvelope = envelopeFor(appStatement, appDim, PAIRWISE, `request:${REQUEST}`, {
  ext: { "shown@1": shown },
  crit: ["shown@1"],
});
const appProof = prove(appEnvelope, { counter: 8 });
const appAnchor = anchorC(appEnvelope, digestOf(appProof));
const appHolderCore = {
  type: "receipt@1",
  statement: appStatement,
  envelope: appEnvelope,
  proof: appProof,
  key: KEY,
  dimension: appDim,
};
const appHolder = { ...appHolderCore, attestations: [accepted(appHolderCore), ledgerReceipt(appAnchor, 42)] };
const appCore = {
  type: "receipt.app@1",
  statement: appStatement,
  envelope: appEnvelope,
  proof: digestOf(appProof),
  dimension: appDim,
};
const appReceipt = { ...appCore, attestations: [accepted(appCore), ledgerReceipt(appAnchor, 42)] };

// ---------------------------------------------------------------- cases

const cases = [];
const ok = (name, input, answer) => cases.push({ name, input, answer: { ok: true, ...answer } });
const no = (name, input, reason) => cases.push({ name, input, answer: { ok: false, reason } });

const receiptCall = (evidence, over = {}) => ({
  op: "receipt",
  trust: trust(over.trust),
  evidence: typeof evidence === "string" ? evidence : JSON.stringify(evidence),
  ...(over.expect === null ? {} : { expect: over.expect ?? { statement: "profile.patch@1", aud: `account:${SIGNER}`, signer: SIGNER } }),
});
function appCall(evidence, over = {}) {
  return {
  op: "app_receipt",
  trust: trust(over.trust),
  evidence: JSON.stringify(evidence),
  expect: { statement: "app.sign@1", aud: `request:${REQUEST}`, signer: PAIRWISE },
  ...(over.holderProof ? { holder_proof: JSON.stringify(over.holderProof) } : {}),
  };
}

// trust
ok(
  "trust",
  { op: "trust", trust: trust() },
  {
    instance: HOST,
    sealer: SEALER_KID,
    issued_at: catalogBody.issued_at,
    keys: Object.values(KEYS).map((k) => ({ kid: k.kid, slot: k[`${NS}-slot`], alg: k.alg })),
    logs: catalogBody.logs,
    registries: catalogBody.registries,
    dimensions: catalogBody.dimensions,
  },
);
no("trust: another master", { op: "trust", trust: trust({ master: ecJwk(otherMaster) }) }, "trust_nomination");
no("trust: private master", { op: "trust", trust: trust({ master: { ...ecJwk(master), d: "AAAA" } }) }, "trust_master");
{
  const j = clone(jwks);
  j.keys[0].x = passkey.x;
  j.keys[0].y = passkey.y;
  no("trust: jwks key swapped", { op: "trust", trust: trust({ jwks: j }) }, "trust_jwks_signature");
}
{
  const j = clone(jwks);
  j.keys[1]["x-clavis-key-generation"] = "202610";
  no("trust: jwks key with an old member", { op: "trust", trust: trust({ jwks: j }) }, "trust_jwks");
}
{
  const j = clone(jwks);
  j.keys.push(clone(j.keys[0]));
  no("trust: jwks kid twice", { op: "trust", trust: trust({ jwks: j }) }, "trust_jwks");
}
{
  const j = { ...clone(jwks), keys: [jwksKey("sign-receipt", signReceipt, "ES256", otherMaster)] };
  no("trust: jwks key signed by another key", { op: "trust", trust: trust({ jwks: j }) }, "trust_jwks_signature");
}
{
  const c = clone(catalog);
  c.issued_at += 1;
  no("trust: catalog changed", { op: "trust", trust: trust({ catalog: c }) }, "trust_catalog_signature");
}
no(
  "trust: catalog signed by another key",
  { op: "trust", trust: trust({ catalog: signCatalog(catalogBody, otherMaster) }) },
  "trust_catalog_signature",
);
no(
  "trust: catalog with a date",
  { op: "trust", trust: trust({ catalog: signCatalog({ ...catalogBody, issued_at: "2026-10-15" }) }) },
  "trust_catalog",
);
no(
  "trust: catalog revokes an unknown verifier",
  {
    op: "trust",
    trust: trust({
      catalog: signCatalog({ ...catalogBody, revoked: [{ verifier: digestOf("x"), reason: "bug", successor: VERIFIER }] }),
    }),
  },
  "trust_catalog",
);
no(
  "trust: catalog nomination by another master",
  { op: "trust", trust: trust({ catalog: signCatalog({ ...catalogBody, sealer: nominate(otherMaster, sealer, SEALER_KID) }) }) },
  "trust_nomination",
);
no(
  "trust: catalog log id",
  {
    op: "trust",
    trust: trust({ catalog: signCatalog({ ...catalogBody, logs: [{ id: "first-party.01", kid: KEYS.fp0.kid }] }) }),
  },
  "trust_catalog",
);

// proof
ok(
  "proof",
  { op: "proof", envelope: JSON.stringify(accountEnvelope), proof: JSON.stringify(accountProof), key: JSON.stringify(KEY) },
  { origin: `https://${HOST}`, counter: 7, alg: -7, backup_eligible: false, backed_up: false },
);
no(
  "proof: another envelope",
  { op: "proof", envelope: JSON.stringify({ ...accountEnvelope, iat: IAT + 1 }), proof: JSON.stringify(accountProof), key: JSON.stringify(KEY) },
  "proof_challenge",
);
no(
  "proof: envelope aud of the old form",
  { op: "proof", envelope: JSON.stringify({ ...accountEnvelope, aud: "me" }), proof: JSON.stringify(accountProof), key: JSON.stringify(KEY) },
  "envelope_shape",
);

// holder receipts
const holderAnswer = (place, extra = {}) => ({
  type: "receipt@1",
  dimension: { digest: digestOf(accountDim), name: "account", verifier: VERIFIER, registry: digestOf(registry), signer: "account" },
  accepted: [{ kid: KEYS.signReceipt.kid, at: IAT + 1 }],
  anchor: place,
  origin: `https://${HOST}`,
  counter: 7,
  statement: accountStatement,
  key: KEY,
  ...extra,
});
ok("receipt", receiptCall(holder), holderAnswer(placeOf(accountAnchor, 41), { key_record: null }));
ok(
  "receipt: key record disclosed",
  receiptCall(holderDisclosed),
  holderAnswer(placeOf(accountAnchor, 41), { key_record: { ...placeOf(openingC(keyRecord), 3), at: keyRecord.at } }),
);
ok("receipt: no expectations", receiptCall(holder, { expect: null }), { type: "receipt@1" });
{
  const r = clone(holder);
  r.attestations.unshift({ type: "witness@1", anything: [1, 2, 3] });
  r.attestations.push({ ...accepted(accountCore), alg: "ML-DSA-65", sig: "AAAA" });
  ok("receipt: unknown attestation and algorithm passed over", receiptCall(r), { type: "receipt@1" });
}
{
  const r = clone(holderDisclosed);
  r.disclosures.push({ type: "note.opening@1", salt: "x" });
  ok("receipt: unknown disclosure passed over", receiptCall(r), { type: "receipt@1" });
}

no("receipt: app receipt to the holder op", receiptCall(appReceipt), "receipt_type");
no("receipt: extra member", receiptCall({ ...holder, extra: 1 }), "receipt_shape");
no("receipt: duplicate key", receiptCall(JSON.stringify(holder).replace('{"type":"receipt@1"', '{"type":"receipt@1","type":"receipt@1"')), "json_duplicate_key");
no("receipt: another master", receiptCall(holder, { trust: { master: ecJwk(otherMaster) } }), "trust_nomination");
no("receipt: registry not passed", receiptCall(holder, { trust: { registries: [] } }), "registry_missing");
no(
  "receipt: dimension not in the catalog",
  receiptCall(holder, { trust: { catalog: signCatalog({ ...catalogBody, dimensions: [digestOf(appDim)] }) } }),
  "dimension_not_in_catalog",
);
no(
  "receipt: registry not in the catalog",
  receiptCall(holder, { trust: { catalog: signCatalog({ ...catalogBody, registries: [] }) } }),
  "registry_not_in_catalog",
);
no("receipt: statement changed", receiptCall({ ...holder, statement: { ...accountStatement, display_name: "Other" } }), "statement_digest");
no("receipt: statement off its rule", receiptCall({ ...holder, statement: { ...accountStatement, display_name: " Hamachi" } }), "statement_shape");
no("receipt: dimension changed", receiptCall({ ...holder, dimension: { ...accountDim, freshness: 600 } }), "dimension_digest");
no("receipt: envelope aud of the old form", receiptCall({ ...holder, envelope: { ...accountEnvelope, aud: "me" } }), "envelope_shape");
no("receipt: envelope aud for another account", receiptCall({ ...holder, envelope: { ...accountEnvelope, aud: "account:eu1.other" } }), "aud");
no("receipt: expected another aud", receiptCall(holder, { expect: { aud: "account:eu1.other" } }), "expect_aud");
no("receipt: expected another signer", receiptCall(holder, { expect: { signer: "eu1.other" } }), "expect_signer");
no("receipt: expected another statement", receiptCall(holder, { expect: { statement: "app.sign@1" } }), "expect_statement");
{
  const r = clone(holder);
  r.proof.signature = appProof.signature;
  no("receipt: proof signature", receiptCall(r), "proof_signature");
}
no("receipt: no accepted", receiptCall({ ...holder, attestations: [holder.attestations[1]] }), "accepted_missing");
no("receipt: no ledger receipt", receiptCall({ ...holder, attestations: [holder.attestations[0]] }), "anchor_missing");
no("receipt: no attestations", receiptCall({ ...holder, attestations: [] }), "attestation_shape");
{
  const r = clone(holder);
  r.attestations[0].sig = accepted(accountCore).sig.replace(/^./, (c) => (c === "A" ? "B" : "A"));
  no("receipt: accepted signature", receiptCall(r), "accepted_signature");
}
no(
  "receipt: accepted for another core",
  receiptCall({ ...holder, attestations: [accepted(appHolderCore), holder.attestations[1]] }),
  "accepted_subject",
);
no(
  "receipt: accepted by a ledger key's kid",
  receiptCall({ ...holder, attestations: [accepted(accountCore, { kid: KEYS.fp0.kid }), holder.attestations[1]] }),
  "accepted_key",
);
no(
  "receipt: accepted by a key not in the jwks",
  receiptCall({ ...holder, attestations: [accepted(accountCore, { key: otherMaster, kid: "clavis-sign-receipt-zzzz" }), holder.attestations[1]] }),
  "accepted_key",
);
no(
  "receipt: accepted signed by another key",
  receiptCall({ ...holder, attestations: [accepted(accountCore, { key: otherMaster }), holder.attestations[1]] }),
  "accepted_signature",
);
no(
  "receipt: ledger receipt for another leaf",
  receiptCall({ ...holder, attestations: [holder.attestations[0], ledgerReceipt(appAnchor, 41)] }),
  "ledger_receipt_leaf",
);
no(
  "receipt: ledger receipt from the anchor log",
  receiptCall({
    ...holder,
    attestations: [holder.attestations[0], ledgerReceipt(accountAnchor, 41, { log: "anchor", key: ledgerAnchor, kid: KEYS.anchor.kid })],
  }),
  "ledger_receipt_log",
);
no(
  "receipt: ledger receipt by a key the catalog does not list",
  receiptCall({
    ...holder,
    attestations: [holder.attestations[0], ledgerReceipt(accountAnchor, 41, { key: ledgerStray, kid: KEYS.stray.kid })],
  }),
  "ledger_note_signer",
);
{
  const r = clone(holder);
  const n = r.attestations[1].note;
  const sigStart = n.lastIndexOf(" ") + 1;
  r.attestations[1].note = n.slice(0, sigStart + 10) + (n[sigStart + 10] === "A" ? "B" : "A") + n.slice(sigStart + 11);
  no("receipt: ledger receipt signature", receiptCall(r), "ledger_note_signature");
}
{
  const r = clone(holder);
  r.attestations[1].note = r.attestations[1].note.replace("\n41\n", "\n42\n");
  no("receipt: ledger receipt index changed", receiptCall(r), "ledger_note_signature");
}
no(
  "receipt: key record not anchored",
  receiptCall({ ...holderDisclosed, attestations: holderDisclosed.attestations.slice(0, 2) }),
  "key_opening_unanchored",
);
{
  const other = { ...keyRecord, credential: b64u(bytes("other credential", 16)) };
  no(
    "receipt: key record of another credential",
    receiptCall({
      ...holderDisclosed,
      attestations: [...holderDisclosed.attestations.slice(0, 2), ledgerReceipt(openingC(other), 3)],
      disclosures: [{ ...opening, record: other }],
    }),
    "key_opening_binding",
  );
}
{
  const other = { ...keyRecord, signer: "eu1.other" };
  no(
    "receipt: key record of another account",
    receiptCall({
      ...holderDisclosed,
      attestations: [...holderDisclosed.attestations.slice(0, 2), ledgerReceipt(openingC(other), 3)],
      disclosures: [{ ...opening, record: other }],
    }),
    "key_opening_binding",
  );
}
no(
  "receipt: two key openings",
  receiptCall({ ...holderDisclosed, disclosures: [opening, opening] }),
  "key_opening_shape",
);

// app dimension
ok("receipt: app dimension, holder", receiptCall(appHolder, { expect: { statement: "app.sign@1", aud: `request:${REQUEST}`, signer: PAIRWISE } }), {
  type: "receipt@1",
  anchor: placeOf(appAnchor, 42),
  counter: 8,
});
ok("app_receipt", appCall(appReceipt), {
  type: "receipt.app@1",
  statement: appStatement,
  envelope: appEnvelope,
  dimension: { digest: digestOf(appDim), name: "app_sign", verifier: VERIFIER, registry: digestOf(registry), signer: "pairwise" },
  accepted: [{ kid: KEYS.signReceipt.kid, at: IAT + 1 }],
  anchor: placeOf(appAnchor, 42),
});
ok("app_receipt: with the holder proof", appCall(appReceipt, { holderProof: appProof }), { type: "receipt.app@1" });
no("app_receipt: another holder proof", appCall(appReceipt, { holderProof: accountProof }), "holder_proof");
no("app_receipt: holder receipt to the app op", appCall(appHolder), "receipt_type");
no("app_receipt: disclosures", appCall({ ...appReceipt, disclosures: [opening] }), "receipt_shape");
/** An app receipt in another dimension the catalog lists. */
function appReceiptIn(dim, envelopeExtra = {}) {
  const envelope = { ...appEnvelope, dimension: digestOf(dim), ...envelopeExtra };
  const core = { ...appCore, envelope, dimension: dim };
  const evidence = { ...core, attestations: [accepted(core), ledgerReceipt(anchorC(envelope, digestOf(appProof)), 43)] };
  const over = { trust: { catalog: signCatalog({ ...catalogBody, dimensions: [...catalogBody.dimensions, digestOf(dim)] }) } };
  return appCall(evidence, over);
}
no(
  "app_receipt: dimension without app receipts",
  appReceiptIn({ ...appDim, name: "app_sign_holder", receipts: ["holder"] }),
  "receipt_kind",
);
{
  const dim = { ...appDim, name: "app_sign_ext", ext: { required: ["shown@1"], allowed: ["other@1", "shown@1"] } };
  ok(
    "app_receipt: unknown extension that is not critical",
    appReceiptIn(dim, { ext: { "other@1": { any: [1] }, "shown@1": shown } }),
    { type: "receipt.app@1", anchor: placeOf(anchorC({ ...appEnvelope, dimension: digestOf(dim), ext: { "other@1": { any: [1] }, "shown@1": shown } }, digestOf(appProof)), 43) },
  );
  no(
    "app_receipt: unknown extension that is critical",
    appReceiptIn(dim, { ext: { "other@1": { any: [1] }, "shown@1": shown }, crit: ["other@1", "shown@1"] }),
    "extension_unknown",
  );
}
{
  const env = { ...appEnvelope };
  delete env.ext;
  delete env.crit;
  no("app_receipt: required extension missing", appCall({ ...appReceipt, envelope: env }), "extension_required");
}
{
  const env = { ...appEnvelope, ext: { "shown@1": shown, "other@1": 1 }, crit: ["other@1", "shown@1"] };
  no("app_receipt: extension not allowed", appCall({ ...appReceipt, envelope: env }), "extension_not_allowed");
}
{
  const env = { ...appEnvelope, ext: { "shown@1": { ...shown, host: "Acme.example" } } };
  no("app_receipt: shown@1 not normalized", appCall({ ...appReceipt, envelope: env }), "envelope_shape");
}
{
  const env = { ...appEnvelope, aud: `request:eu1.another` };
  no("app_receipt: aud for another request", appCall({ ...appReceipt, envelope: env }), "aud");
}

// ledger notes
ok(
  "ledger_note: receipt",
  { op: "ledger_note", trust: trust(), note: ledgerReceipt(accountAnchor, 41).note },
  {
    log: "first-party.0",
    kid: KEYS.fp0.kid,
    body: { kind: "receipt", origin: `${HOST}/ledger/first-party.0`, index: 41, leaf_hash: b64(leafHash(accountAnchor)) },
  },
);
{
  const rootHash = sha256("root");
  const body = `${HOST}/ledger/anchor\n12\n${b64(rootHash)}\ntime ${IAT}\n`;
  ok(
    "ledger_note: checkpoint",
    { op: "ledger_note", trust: trust(), note: note(body, ledgerAnchor, KEYS.anchor.kid) },
    { log: "anchor", kid: KEYS.anchor.kid, body: { kind: "checkpoint", origin: `${HOST}/ledger/anchor`, size: 12, root: b64(rootHash), time: IAT } },
  );
  no(
    "ledger_note: checkpoint signed by another log's key",
    { op: "ledger_note", trust: trust(), note: note(body, ledgerFp0, KEYS.fp0.kid) },
    "ledger_note_signer",
  );
  ok(
    "ledger_note: an org log's checkpoint, signed by a ledger-log key",
    { op: "ledger_note", trust: trust(), note: note(body.replace("/ledger/anchor", `/ledger/eu1.${APP}`), ledgerAnchor, KEYS.anchor.kid) },
    { log: `eu1.${APP}`, kid: KEYS.anchor.kid },
  );
  no(
    "ledger_note: origin of an unknown log",
    { op: "ledger_note", trust: trust(), note: note(body.replace("/ledger/anchor", "/ledger/archive"), ledgerAnchor, KEYS.anchor.kid) },
    "ledger_note_log",
  );
  no(
    "ledger_note: an org log's note signed by a key of another slot",
    { op: "ledger_note", trust: trust(), note: note(body.replace("/ledger/anchor", `/ledger/eu1.${APP}`), stateAttest, KEYS.stateAttest.kid) },
    "ledger_note_signer",
  );
}

// ---------------------------------------------------------------- delegation records

const MANDATE_ID = "6f1d2c3b-4a5e-4f60-8172-9a8b7c6d5e4f";
const REQUEST_M = `eu1.${b64u(bytes("mandate request", 18))}`;
const terms = {
  type: "mandate.terms@1",
  operations: [
    { name: "book", label: "Book a room" },
    { name: "cancel", label: "Cancel a booking" },
  ],
  uses: 3,
  not_after: IAT + 86400,
  amount: { currency: "JPY", total: 30000, per_use: 15000 },
  agent: { id: "agent-1", label: "Travel agent" },
};

/** An app receipt for a grant statement, with its anchor on first-party.0. */
function grantReceipt(statement, index) {
  const envelope = envelopeFor(statement, mandateDim, PAIRWISE, `request:${statement.request}`);
  const proof = prove(envelope, { counter: 20 + index });
  const core = { type: "receipt.app@1", statement, envelope, proof: digestOf(proof), dimension: mandateDim };
  return { envelope, receipt: { ...core, attestations: [accepted(core), ledgerReceipt(anchorC(envelope, digestOf(proof)), index)] } };
}
const grantStatement = { type: "mandate.grant@1", request: REQUEST_M, app: APP, mandate: MANDATE_ID, terms: digestOf(terms) };
const grant = grantReceipt(grantStatement, 50);
const GRANT = digestOf(grant.envelope);

const OPERATE_KEY = { kty: "OKP", crv: "Ed25519", x: appOperate.x };
function appJwt(request, at, over = {}) {
  const header = b64u(Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })));
  const payloadText =
    over.payloadText ??
    JSON.stringify({
      iss: `app:${APP}`,
      app_id: APP,
      aud: "clavis-ledger",
      body_sha256: hex(sha256(jcs(request))),
      iat: at - 5,
      exp: at + 60,
      ...over.payload,
    });
  const payload = b64u(Buffer.from(payloadText));
  const sig = sign(null, Buffer.from(`${header}.${payload}`), (over.key ?? appOperate).priv);
  return `${header}.${payload}.${b64u(sig)}`;
}
const recordDigest = (r) => {
  const { sigs: _sigs, ...body } = r;
  return digestOf(body);
};
function attestRecord(body, { key = mandateAttest, kid = KEYS.mandateAttest.kid } = {}) {
  return { ...body, sigs: [{ kid, alg: "ES256", sig: es256(key, jcs(body)) }] };
}
function useRecord(seq, prev, { amount = 10000, at = IAT + 100 * seq, request: over = {}, jwt = {}, totals, sign: signOver } = {}) {
  const request = {
    type: "mandate.use_request@1",
    mandate: MANDATE_ID,
    use: `0000000${seq}-0000-4000-8000-000000000000`,
    operation: "book",
    call: digestOf(`call ${seq}`),
    amount,
    agent: "agent-1",
    ...over,
  };
  const spent = (prev?.totals.amount ?? 0) + (request.amount ?? 0);
  return attestRecord(
    {
      type: "mandate.use@1",
      grant: GRANT,
      seq,
      prev: prev ? recordDigest(prev) : null,
      request,
      app: { jwt: appJwt(jwt.request ?? request, at, jwt), key: OPERATE_KEY },
      totals: totals ?? { uses: seq, amount: spent },
      at,
    },
    signOver,
  );
}
const use1 = useRecord(1, null);
const use2 = useRecord(2, use1);
function closeRecord(over = {}, signOver) {
  return attestRecord(
    { type: "mandate.close@1", grant: GRANT, mandate: MANDATE_ID, reason: "revoked_by_holder", uses: 2, last: recordDigest(use2), at: IAT + 500, ...over },
    signOver,
  );
}
const close = closeRecord();
const historyCall = (over = {}) => ({
  op: "mandate_history",
  trust: trust(over.trust),
  grant: JSON.stringify(over.grant ?? grant.receipt),
  terms: JSON.stringify(over.terms ?? terms),
  uses: (over.uses ?? [use1, use2]).map((u) => JSON.stringify(u)),
  ...(over.close === null ? {} : { close: JSON.stringify(over.close ?? close) }),
});

ok("mandate_history", historyCall(), {
  grant: { type: "mandate.grant@1", mandate: MANDATE_ID, app: APP, request: REQUEST_M, on_behalf: null },
  terms,
  uses: [
    { seq: 1, operation: "book", at: IAT + 100, totals: { uses: 1, amount: 10000 } },
    { seq: 2, operation: "book", at: IAT + 200, totals: { uses: 2, amount: 20000 } },
  ],
  close: { reason: "revoked_by_holder", at: IAT + 500, uses: 2 },
});
ok("mandate_history: open, no uses", historyCall({ uses: [], close: null }), { uses: [], close: null });
ok("mandate_history: one use, still open", historyCall({ uses: [use1], close: null }), { close: null });
{
  const statement = { ...grantStatement, type: "mandate.grant.on_behalf@1", org: `eu1.${APP}`, domain: "acme.example" };
  const g = grantReceipt(statement, 51);
  const c = attestRecord({
    type: "mandate.close@1",
    grant: digestOf(g.envelope),
    mandate: MANDATE_ID,
    reason: "signer_designation_ended",
    uses: 0,
    last: null,
    at: IAT + 500,
  });
  ok("mandate_history: in an organization's name, closed when the designation ended", historyCall({ grant: g.receipt, uses: [], close: c }), {
    grant: { type: "mandate.grant.on_behalf@1", mandate: MANDATE_ID, app: APP, request: REQUEST_M, on_behalf: { org: `eu1.${APP}`, domain: "acme.example" } },
    close: { reason: "signer_designation_ended", at: IAT + 500, uses: 0 },
  });
}
no("mandate_history: grant is not a grant", historyCall({ grant: appReceipt }), "mandate_grant");
no("mandate_history: grant receipt tampered", historyCall({ grant: { ...grant.receipt, statement: { ...grantStatement, mandate: "00000000-0000-4000-8000-000000000000" } } }), "statement_digest");
no("mandate_history: other terms", historyCall({ terms: { ...terms, uses: 4 } }), "mandate_terms_digest");
no(
  "mandate_history: terms out of order",
  historyCall({ terms: { ...terms, operations: [...terms.operations].reverse() } }),
  "mandate_terms_shape",
);
no(
  "mandate_history: use signed by the receipt key",
  historyCall({ uses: [useRecord(1, null, { sign: { key: signReceipt, kid: KEYS.signReceipt.kid } })], close: null }),
  "mandate_attest_signature",
);
no("mandate_history: jwt by another key", historyCall({ uses: [useRecord(1, null, { jwt: { key: ledgerStray } })], close: null }), "mandate_app_jwt_signature");
no("mandate_history: jwt for another audience", historyCall({ uses: [useRecord(1, null, { jwt: { payload: { aud: "other" } } })], close: null }), "mandate_app_jwt_aud");
no("mandate_history: jwt for another app", historyCall({ uses: [useRecord(1, null, { jwt: { payload: { app_id: "other-app" } } })], close: null }), "mandate_app_jwt_app");
no(
  "mandate_history: jwt over another request",
  historyCall({ uses: [useRecord(1, null, { jwt: { request: { type: "mandate.use_request@1", other: 1 } } })], close: null }),
  "mandate_app_jwt_body",
);
no("mandate_history: jwt expired", historyCall({ uses: [useRecord(1, null, { jwt: { payload: { exp: IAT } } })], close: null }), "mandate_app_jwt_time");
no("mandate_history: jwt time with a fraction", historyCall({ uses: [useRecord(1, null, { jwt: { payload: { iat: IAT + 95.5 } } })], close: null }), "mandate_app_jwt_time");
{
  const at = IAT + 100;
  const body = JSON.stringify({ iss: `app:${APP}`, app_id: APP, aud: "clavis-ledger", body_sha256: "x", iat: at, exp: at + 60 });
  const dup = body.replace("{", '{"aud":"other",');
  no("mandate_history: jwt with a repeated key", historyCall({ uses: [useRecord(1, null, { jwt: { payloadText: dup } })], close: null }), "mandate_app_jwt_shape");
}
no("mandate_history: over the per-use amount", historyCall({ uses: [useRecord(1, null, { amount: 20000 })], close: null }), "mandate_outside");
no("mandate_history: another operation", historyCall({ uses: [useRecord(1, null, { request: { operation: "pay" } })], close: null }), "mandate_outside");
no("mandate_history: totals that do not add up", historyCall({ uses: [useRecord(1, null, { totals: { uses: 1, amount: 15000 } })], close: null }), "mandate_totals");
no("mandate_history: another mandate", historyCall({ uses: [useRecord(1, null, { request: { mandate: "00000000-0000-4000-8000-000000000000" } })], close: null }), "mandate_mismatch");
no("mandate_history: before the grant", historyCall({ uses: [useRecord(1, null, { at: IAT - 10 })], close: null }), "mandate_before_grant");
no("mandate_history: uses out of order", historyCall({ uses: [use2, use1], close: null }), "mandate_use_chain");
{
  const other = useRecord(2, useRecord(1, null, { amount: 5000 }));
  no("mandate_history: second use after another first", historyCall({ uses: [use1, other], close: null }), "mandate_use_chain");
}
no("mandate_history: use with an old member", historyCall({ uses: [{ ...use1, extra: 1 }], close: null }), "mandate_use_shape");
no("mandate_history: signer_designation_ended without an organization", historyCall({ close: closeRecord({ reason: "signer_designation_ended" }) }), "mandate_close_reason");
no("mandate_history: exhausted too early", historyCall({ close: closeRecord({ reason: "exhausted" }) }), "mandate_close_exhausted");
no("mandate_history: expired at another time", historyCall({ close: closeRecord({ reason: "expired" }) }), "mandate_close_expired");
no("mandate_history: close before the last use", historyCall({ close: closeRecord({ uses: 1, last: recordDigest(use1) }) }), "mandate_close_last");
no("mandate_history: close for another grant", historyCall({ close: closeRecord({ grant: digestOf("other") }) }), "mandate_grant_digest");
no("mandate_history: close signed by another key", historyCall({ close: closeRecord({}, { key: otherMaster }) }), "mandate_attest_signature");
no("mandate_history: close@2 is gone", historyCall({ close: closeRecord({ type: "mandate.close@2" }) }), "mandate_close_shape");

// ---------------------------------------------------------------- event chains

function content(seq, over = {}) {
  return {
    salt: b64u(bytes(`event salt ${seq}`)),
    change: "profile.patch@1",
    at: IAT + seq,
    payload: { display_name: `Name ${seq}` },
    receipt: seq === 2 ? JSON.stringify(holder) : null,
    ...over,
  };
}
function commitOf(c) {
  const { salt, ...rest } = c;
  return `sha256:${b64u(sha256(Buffer.concat([Buffer.from("clavis.event.v1"), Buffer.from(salt, "base64url"), Buffer.from(jcs({ type: "event.content@1", ...rest }))])))}`;
}
function attestDoc(body, { key = stateAttest, kid = KEYS.stateAttest.kid, alg = "EdDSA" } = {}) {
  return { ...body, attest: { kid, alg, sig: b64u(sign(null, Buffer.from(jcs(body)), key.priv)) } };
}
const skeletonDigest = (s) => {
  const { attest: _a, ...body } = s;
  return digestOf(body);
};
function skeleton(seq, prev, over = {}, signOver) {
  return attestDoc(
    {
      type: "event@1",
      actor: SIGNER,
      seq,
      prev: prev ? skeletonDigest(prev) : null,
      commit: commitOf(content(seq)),
      envelope: seq === 2 ? digestOf(accountEnvelope) : null,
      leaves: seq === 2 ? [accountAnchor] : [],
      ...over,
    },
    signOver,
  );
}
const ev1 = skeleton(1, null);
const ev2 = skeleton(2, ev1);
const ev3 = skeleton(3, ev2);
const snapshot = attestDoc({ type: "state.snapshot@1", actor: SIGNER, seq: 2, head: skeletonDigest(ev2), state: { display_name: "Name 2" } });
const chainCall = (over = {}) => ({
  op: "chain",
  trust: trust(),
  events: (over.events ?? [ev1, ev2, ev3]).map((e) => JSON.stringify(e)),
  from: over.from ?? null,
  ...(over.contents === null ? {} : { contents: (over.contents ?? [[1, content(1)], [2, content(2)]]).map(([seq, c]) => ({ seq, content: JSON.stringify(c) })) }),
  ...(over.snapshot === null ? {} : { snapshot: JSON.stringify(over.snapshot ?? snapshot) }),
});

ok("chain", chainCall(), {
  actor: SIGNER,
  first: 1,
  last: 3,
  head: skeletonDigest(ev3),
  opened: [
    { seq: 1, change: "profile.patch@1", at: IAT + 1 },
    { seq: 2, change: "profile.patch@1", at: IAT + 2 },
  ],
  snapshot: 2,
});
ok("chain: from the middle", chainCall({ events: [ev2, ev3], from: skeletonDigest(ev1), contents: null, snapshot: null }), { first: 2, last: 3, opened: [], snapshot: null });
no("chain: from another skeleton", chainCall({ events: [ev2, ev3], from: skeletonDigest(ev3), contents: null, snapshot: null }), "chain_link");
no("chain: a skeleton missing", chainCall({ events: [ev1, ev3], contents: null, snapshot: null }), "chain_link");
no("chain: signed by a ledger key", chainCall({ events: [ev1, skeleton(2, ev1, {}, { key: ledgerFp0, kid: KEYS.fp0.kid })], contents: null, snapshot: null }), "chain_attest");
no("chain: alg written as Ed25519", chainCall({ events: [skeleton(1, null, {}, { alg: "Ed25519" })], contents: null, snapshot: null }), "chain_attest");
no(
  "chain: another actor",
  chainCall({ events: [ev1, skeleton(2, ev1, { actor: `eu1.${APP}` })], contents: null, snapshot: null }),
  "chain_actor",
);
no("chain: first with a prev", chainCall({ events: [skeleton(1, ev3)], contents: null, snapshot: null }), "chain_shape");
no("chain: leaf twice", chainCall({ events: [skeleton(1, null, { leaves: [accountAnchor, accountAnchor] })], contents: null, snapshot: null }), "chain_shape");
no("chain: content changed", chainCall({ contents: [[1, content(1, { payload: { display_name: "Other" } })]] }), "chain_content_commit");
no("chain: content for no skeleton", chainCall({ contents: [[9, content(1)]] }), "chain_content_seq");
no("chain: content with an extra member", chainCall({ contents: [[1, { ...content(1), extra: 1 }]] }), "chain_content_shape");
no("chain: snapshot at another head", chainCall({ snapshot: { ...snapshot, head: skeletonDigest(ev3) } }), "chain_snapshot_head");
no(
  "chain: snapshot signed by another key",
  chainCall({ snapshot: attestDoc({ type: "state.snapshot@1", actor: SIGNER, seq: 2, head: skeletonDigest(ev2), state: {} }, { key: ledgerStray }) }),
  "chain_attest",
);

// ---------------------------------------------------------------- ledger evidence bundles

const ORG_LOG = `eu1.${APP}`;
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));
function mth(hashes) {
  if (hashes.length === 1) return hashes[0];
  let k = 1;
  while (k * 2 < hashes.length) k *= 2;
  return nodeHash(mth(hashes.slice(0, k)), mth(hashes.slice(k)));
}
function path(m, hashes) {
  if (hashes.length === 1) return [];
  let k = 1;
  while (k * 2 < hashes.length) k *= 2;
  return m < k ? [...path(m, hashes.slice(0, k)), mth(hashes.slice(k))] : [...path(m - k, hashes.slice(k)), mth(hashes.slice(0, k))];
}
const record = { invoice: "INV-1", amount: 12.5, lines: [1, 2.25, -0] };
const recordSalt = bytes("record salt");
const recordC = hex(sha256(Buffer.concat([Buffer.from("clavis.commit.v1"), recordSalt, Buffer.from(jcsAny(record))])));
const otherLeaves = [0, 1, 3, 4].map((i) => leafHash(hex(bytes(`other leaf ${i}`))));
const leafHashes = [otherLeaves[0], otherLeaves[1], leafHash(recordC), otherLeaves[2], otherLeaves[3]];
function bundleFor(log, { key = ledgerFp0, kid = KEYS.fp0.kid, host = HOST, anchorHost = HOST } = {}) {
  const cpBody = `${host}/ledger/${log}\n5\n${b64(mth(leafHashes))}\ntime ${IAT + 60}\n`;
  const receiptBody = `clavis.ledger.receipt/v1\n${host}/ledger/${log}\n2\n${b64(leafHashes[2])}\n`;
  const anchorLeaves = [leafHash(hex(bytes("anchor 0"))), leafHash(hex(sha256(cpBody))), leafHash(hex(bytes("anchor 2")))];
  const anchorBody = `${anchorHost}/ledger/anchor\n3\n${b64(mth(anchorLeaves))}\ntime ${IAT + 120}\n`;
  return {
    type: "ledger.bundle@1",
    log,
    leaf: { v: 1, c: recordC },
    index: 2,
    receipt: note(receiptBody, key, kid),
    checkpoint: note(cpBody, key, kid),
    inclusion: path(2, leafHashes).map(b64),
    opening: { salt: b64u(recordSalt), record },
    anchor: {
      index: 1,
      checkpoint: note(anchorBody, ledgerAnchor, KEYS.anchor.kid),
      inclusion: path(1, anchorLeaves).map(b64),
      tsa: [{ url: "https://tsa.example/", response: b64(Buffer.from("not a token")) }],
    },
  };
}
const orgBundle = bundleFor(ORG_LOG);
const bundleCall = (evidence) => ({ op: "bundle", trust: trust(), evidence: typeof evidence === "string" ? evidence : JSON.stringify(evidence) });

ok("bundle: an org log, with opening and anchor", bundleCall(orgBundle), {
  log: ORG_LOG,
  index: 2,
  committed_by: IAT + 60,
  opening: true,
  anchor: { anchored_by: IAT + 120, tsa: 0 },
});
{
  const { opening: _o, anchor: _a, ...bare } = orgBundle;
  ok("bundle: leaf only", bundleCall(bare), { opening: false, anchor: null });
}
ok("bundle: a first-party shard", bundleCall(bundleFor("first-party.0")), { log: "first-party.0", opening: true });
no("bundle: a first-party shard signed by an unlisted key", bundleCall(bundleFor("first-party.0", { key: ledgerStray, kid: KEYS.stray.kid })), "ledger_note_signer");
no("bundle: another salt", bundleCall({ ...orgBundle, opening: { salt: b64u(bytes("other")), record } }), "bundle_opening");
no("bundle: record changed", bundleCall({ ...orgBundle, opening: { salt: b64u(recordSalt), record: { ...record, amount: 12.25 } } }), "bundle_opening");
no("bundle: inclusion proof swapped", bundleCall({ ...orgBundle, inclusion: [...orgBundle.inclusion].reverse() }), "bundle_inclusion");
no("bundle: another index", bundleCall({ ...orgBundle, index: 3 }), "bundle_receipt");
no("bundle: notes of another log", bundleCall({ ...orgBundle, log: `eu1.${MANDATE_ID}` }), "bundle_log");
no("bundle: anchor on another host", bundleCall(bundleFor(ORG_LOG, { anchorHost: "other.example" })), "bundle_anchor");
no("bundle: anchor inclusion wrong", bundleCall({ ...orgBundle, anchor: { ...orgBundle.anchor, index: 0 } }), "bundle_anchor");
no("bundle: the v1 shape", bundleCall({ version: 1, log_id: ORG_LOG, jwks: jwks, leaf: orgBundle.leaf }), "bundle_shape");
no("bundle: anchor of the wrong log", bundleCall({ ...orgBundle, anchor: { ...orgBundle.anchor, checkpoint: orgBundle.checkpoint } }), "bundle_anchor");
no(
  "bundle: record with a repeated key",
  bundleCall(JSON.stringify(orgBundle).replace('"invoice":"INV-1"', '"invoice":"INV-1","invoice":"INV-2"')),
  "json_duplicate_key",
);

const out = join(root, "vectors", "genesis", "ops-1.json");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify({ about: "Calls and the answers FORMATS.md requires. Written by tools/genesis-vectors.mjs.", cases }, null, 1)}\n`);
console.log(`${cases.length} cases → ${out}`);

// ---------------------------------------------------------------- host conformance
// Scenarios for the JavaScript and Go hosts (ABI.md §Hosts). `collatio` is the real module,
// which the harness loads from out/collatio.wasm under the digest the scenario declares.

const OTHER = `sha256:${b64u(sha256("collatio successor module"))}`;
const verifierEntry = (digest) => ({ digest, source: { repo: "https://github.com/clavisnexus/collatio", tag: "v1.0.1", commit: "b".repeat(40) } });
const catalogWith = (over) => signCatalog({ ...catalogBody, verifiers: [verifierEntry(VERIFIER), verifierEntry(OTHER)], ...over });
const NOW = catalogBody.issued_at + 3600;
const at = (input, now = NOW) => ({ ...input, now });
const hostReceipt = (over = {}) => at(receiptCall(holder, over));
const scenarios = [
  { name: "abi version 2 is refused", modules: [{ file: "abi2.wasm" }], load_error: "unsupported_abi" },
  { name: "a missing export is refused", modules: [{ file: "no-abi-version.wasm" }], load_error: "unsupported_abi" },
  {
    name: "after a trap the next call runs on a new instance",
    modules: [{ file: "stub.wasm" }],
    calls: [
      { raw: "T", answer: { ok: false, reason: "verifier_trap" } },
      { raw: "{}", answer: { ok: true, stub: true } },
    ],
    instantiations: 2,
  },
  {
    name: "an instance over the memory limit is replaced",
    modules: [{ file: "grow.wasm" }],
    max_memory: 8 * 65536,
    calls: [
      { raw: "{}", answer: { ok: true, stub: true } },
      { raw: "{}", answer: { ok: true, stub: true } },
      { raw: "{}", answer: { ok: true, stub: true } },
    ],
    instantiations: 3,
  },
  {
    name: "a receipt on the module it names",
    modules: [{ file: "collatio", digest: VERIFIER }],
    calls: [{ input: hostReceipt(), answer: { ok: true, type: "receipt@1", verifier: VERIFIER }, absent: ["catalog_stale"] }],
  },
  {
    name: "the named module is run when the default is another",
    modules: [
      { file: "collatio", digest: OTHER },
      { file: "collatio", digest: VERIFIER },
    ],
    calls: [{ input: hostReceipt({ trust: { catalog: catalogWith({}) } }), answer: { ok: true, verifier: VERIFIER } }],
  },
  {
    name: "a revoked verifier is followed to its successor",
    modules: [{ file: "collatio", digest: OTHER }],
    calls: [
      {
        input: hostReceipt({ trust: { catalog: catalogWith({ revoked: [{ verifier: VERIFIER, reason: "test", successor: OTHER }] }) } }),
        answer: { ok: true, verifier: OTHER },
      },
    ],
  },
  {
    name: "a revoked verifier is not run",
    modules: [{ file: "collatio", digest: VERIFIER }],
    calls: [
      {
        input: hostReceipt({ trust: { catalog: catalogWith({ revoked: [{ verifier: VERIFIER, reason: "test", successor: OTHER }] }) } }),
        answer: { ok: false, reason: "verifier_unavailable" },
      },
    ],
  },
  {
    name: "a module the catalog does not list is not run",
    modules: [{ file: "collatio", digest: OTHER }],
    calls: [{ input: hostReceipt(), answer: { ok: false, reason: "verifier_unavailable" } }],
  },
  {
    name: "the named module is not held",
    modules: [{ file: "collatio", digest: OTHER }],
    calls: [{ input: hostReceipt({ trust: { catalog: catalogWith({}) } }), answer: { ok: false, reason: "verifier_unavailable" } }],
  },
  {
    name: "a stale catalog is marked",
    modules: [{ file: "collatio", digest: VERIFIER }],
    calls: [
      { input: at(receiptCall(holder), catalogBody.issued_at + 8 * 86400), answer: { ok: true, catalog_stale: true } },
      { input: at({ op: "trust", trust: trust() }, catalogBody.issued_at + 8 * 86400), answer: { ok: true, catalog_stale: true } },
    ],
  },
  {
    name: "the trust chain's refusal is the answer",
    modules: [{ file: "collatio", digest: VERIFIER }],
    calls: [{ input: hostReceipt({ trust: { master: ecJwk(otherMaster) } }), answer: { ok: false, reason: "trust_nomination" } }],
  },
  {
    name: "other operations run on a listed module",
    modules: [{ file: "collatio", digest: VERIFIER }],
    calls: [
      { input: at(chainCall()), answer: { ok: true, last: 3 }, absent: ["verifier"] },
      { input: at({ op: "inclusion", index: 0, size: 1, leaf_hash: b64(leafHashes[0]), proof: [], root: b64(leafHashes[0]) }), answer: { ok: true } },
    ],
  },
];
const hostsOut = join(root, "conformance", "hosts-1.json");
mkdirSync(dirname(hostsOut), { recursive: true });
writeFileSync(
  hostsOut,
  `${JSON.stringify({ about: "Host conformance scenarios (ABI.md §Hosts). Written by tools/genesis-vectors.mjs.", scenarios }, null, 1)}\n`,
);
console.log(`${scenarios.length} host scenarios → ${hostsOut}`);
