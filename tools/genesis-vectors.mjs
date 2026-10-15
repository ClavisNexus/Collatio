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
};
const jwks = { keys: Object.values(KEYS), sealer: nomination };

const registry = {
  type: "registry@1",
  statements: {
    "profile.patch@1": { aud: "account:<signer>", fields: { display_name: "text(200)" } },
    "app.sign@1": { aud: "request:<request>", fields: { request: "id", app: "app", digest: "bytes32" } },
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
  dimensions: [digestOf(accountDim), digestOf(appDim)],
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
  ...extra,
});
ok("receipt", receiptCall(holder), holderAnswer({ log: "first-party.0", index: 41 }, { key_record: null }));
ok(
  "receipt: key record disclosed",
  receiptCall(holderDisclosed),
  holderAnswer({ log: "first-party.0", index: 41 }, { key_record: { log: "first-party.0", index: 3, at: keyRecord.at } }),
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
  anchor: { log: "first-party.0", index: 42 },
  counter: 8,
});
ok("app_receipt", appCall(appReceipt), {
  type: "receipt.app@1",
  statement: appStatement,
  envelope: appEnvelope,
  dimension: { digest: digestOf(appDim), name: "app_sign", verifier: VERIFIER, registry: digestOf(registry), signer: "pairwise" },
  accepted: [{ kid: KEYS.signReceipt.kid, at: IAT + 1 }],
  anchor: { log: "first-party.0", index: 42 },
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
    { type: "receipt.app@1", anchor: { log: "first-party.0", index: 43 } },
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
  no(
    "ledger_note: origin of an org log",
    { op: "ledger_note", trust: trust(), note: note(body.replace("/ledger/anchor", `/ledger/eu1.${APP}`), ledgerAnchor, KEYS.anchor.kid) },
    "ledger_note_log",
  );
}

const out = join(root, "vectors", "genesis", "ops-1.json");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify({ about: "Calls and the answers FORMATS.md requires. Written by tools/genesis-vectors.mjs.", cases }, null, 1)}\n`);
console.log(`${cases.length} cases → ${out}`);
