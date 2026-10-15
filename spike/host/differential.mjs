// §18.10 items 3, 4, 5 and 8 in Node.
//   node spike/host/differential.mjs [path/to/collatio_spike.wasm]
// - Wycheproof (RSA PKCS#1 v1.5 2048–8192, ECDSA P-256 DER and P1363): Collatio vs node:crypto vs expected.
// - Random keys and mutated signatures: Collatio vs node:crypto.
// - RFC 8785 numbers: Collatio vs ECMAScript String(x) on edge cases and random doubles.
// - Trap recovery and memory after large inputs.
import { readFileSync, readdirSync } from "node:fs";
import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { instantiate, resilient } from "./collatio.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.argv[2] ?? join(here, "../out/collatio_spike.wasm");
const module = new WebAssembly.Module(readFileSync(wasmPath));
const c = instantiate(module);
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const hex2b64u = (h) => b64u(Buffer.from(h, "hex"));
const report = { wasm: wasmPath, sections: {} };
let failures = 0;

function note(section, key, n = 1) {
  report.sections[section] ??= {};
  report.sections[section][key] = (report.sections[section][key] ?? 0) + n;
}
function mismatch(section, detail) {
  failures += 1;
  note(section, "mismatch");
  if ((report.sections[section].examples ??= []).length < 10) report.sections[section].examples.push(detail);
}

// --- Wycheproof ---------------------------------------------------------------------------
const wdir = join(here, "../vectors/wycheproof");
for (const file of readdirSync(wdir).filter((f) => f.endsWith(".json")).sort()) {
  const j = JSON.parse(readFileSync(join(wdir, file), "utf8"));
  const section = `wycheproof/${file.replace(/_test\.json$/, "")}`;
  for (const g of j.testGroups) {
    let call;
    let nodeKey;
    let nodeOpts = {};
    let alg;
    if (file.startsWith("rsa_signature")) {
      alg = g.sha.replace("SHA-", "sha");
      nodeKey = createPublicKey({ key: g.publicKeyJwk ?? g.keyJwk ?? { kty: "RSA", n: hex2b64u(g.publicKey.modulus), e: hex2b64u(g.publicKey.publicExponent) }, format: "jwk" });
      const jwk = nodeKey.export({ format: "jwk" });
      call = (t) => ({ op: "rsa", input: { n: jwk.n, e: jwk.e, msg: hex2b64u(t.msg), sig: hex2b64u(t.sig), hash: alg } });
    } else {
      alg = "sha256";
      const pad = (h) => h.replace(/^00/, "").padStart(64, "0");
      const x = pad(g.publicKey.wx);
      const y = pad(g.publicKey.wy);
      nodeKey = createPublicKey({ key: { kty: "EC", crv: "P-256", x: hex2b64u(x), y: hex2b64u(y) }, format: "jwk" });
      const format = file.includes("p1363") ? "raw" : "der";
      nodeOpts = { dsaEncoding: format === "raw" ? "ieee-p1363" : "der" };
      call = (t) => ({ op: "p256", input: { key: { x: hex2b64u(x), y: hex2b64u(y) }, msg: hex2b64u(t.msg), sig: hex2b64u(t.sig), format } });
    }
    for (const t of g.tests) {
      const { op, input } = call(t);
      const got = c.call(op, input);
      let nodeOk;
      try {
        nodeOk = verify(alg, Buffer.from(t.msg, "hex"), { key: nodeKey, ...nodeOpts }, Buffer.from(t.sig, "hex"));
      } catch {
        nodeOk = false;
      }
      note(section, `collatio_${got.ok ? "accept" : got.reason}`);
      const expected = t.result; // valid | invalid | acceptable
      const keyRefused = got.reason === "bad_key";
      if (expected === "valid" && !got.ok && !keyRefused) mismatch(section, { tcId: t.tcId, expected, got, comment: t.comment });
      if (expected === "invalid" && got.ok) mismatch(section, { tcId: t.tcId, expected, got, comment: t.comment, flags: t.flags });
      if (expected === "acceptable") note(section, `acceptable_${got.ok ? "accepted" : "refused"}`);
      if (!keyRefused && got.ok !== nodeOk) note(section, "differs_from_node"), report.sections[section].node_examples ??= [], report.sections[section].node_examples.length < 5 && report.sections[section].node_examples.push({ tcId: t.tcId, expected, collatio: got, node: nodeOk, flags: t.flags });
    }
  }
}

// --- Random keys, mutated signatures --------------------------------------------------------
function flip(buf) {
  const out = Buffer.from(buf);
  const i = Math.floor(Math.random() * out.length);
  out[i] ^= 1 << Math.floor(Math.random() * 8);
  return out;
}
for (const bits of [2048, 3072, 4096]) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = publicKey.export({ format: "jwk" });
  for (const hash of ["sha256", "sha384", "sha512"]) {
    for (let i = 0; i < 40; i++) {
      const msg = randomBytes(Math.floor(Math.random() * 300));
      let sig = sign(hash, msg, privateKey);
      if (i % 2) sig = flip(sig);
      const got = c.call("rsa", { n: jwk.n, e: jwk.e, msg: b64u(msg), sig: b64u(sig), hash });
      const want = verify(hash, msg, publicKey, sig);
      note("random/rsa", got.ok === want ? "agree" : "disagree");
      if (got.ok !== want) mismatch("random/rsa", { bits, hash, i, got, want });
    }
  }
}
for (let k = 0; k < 20; k++) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  for (let i = 0; i < 20; i++) {
    const msg = randomBytes(37 + Math.floor(Math.random() * 300));
    let sig = sign("sha256", msg, privateKey);
    if (i % 2) sig = flip(sig);
    const got = c.call("p256", { key: { x: jwk.x, y: jwk.y }, msg: b64u(msg), sig: b64u(sig), format: "der" });
    let want;
    try {
      want = verify("sha256", msg, publicKey, sig);
    } catch {
      want = false;
    }
    note("random/p256", got.ok === want ? "agree" : "disagree");
    if (got.ok !== want) mismatch("random/p256", { i, got, want, sig: b64u(sig) });
  }
}
for (let k = 0; k < 10; k++) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "jwk" }).x;
  for (let i = 0; i < 20; i++) {
    const msg = randomBytes(Math.floor(Math.random() * 300));
    let sig = sign(null, msg, privateKey);
    if (i % 2) sig = flip(sig);
    const got = c.call("ed25519", { key: raw, msg: b64u(msg), sig: b64u(sig) });
    const want = verify(null, msg, publicKey, sig);
    note("random/ed25519", got.ok === want ? "agree" : "disagree");
    if (got.ok !== want) mismatch("random/ed25519", { i, got, want });
  }
}

// --- RFC 8785 numbers -----------------------------------------------------------------------
const dv = new DataView(new ArrayBuffer(8));
const bitsOf = (x) => (dv.setFloat64(0, x), dv.getBigUint64(0).toString(16).padStart(16, "0"));
const edge = [0, -0, 1, -1, 0.1, 0.5, 1 / 3, 2 ** 53, 2 ** 53 + 2, -(2 ** 53), 1e21, 1e21 - 65536, 9.999999999999999e20, 1e-6, 1e-7, 1.5e-7, 123e-20, 5e-324, -5e-324, Number.MAX_VALUE, Number.MIN_VALUE, 2 ** -1074, 4.35, 0.000001, 1e300, 333333333.3333333, 1e23, 9007199254740993, 295147905179352830000, 1.7976931348623157e308, 4.940656458412465e-324];
const randomBits = () => (dv.setUint32(0, (Math.random() * 2 ** 32) >>> 0), dv.setUint32(4, (Math.random() * 2 ** 32) >>> 0), dv.getFloat64(0));
const randomDecimal = () => Number((Math.random() * 10 ** Math.floor(Math.random() * 30 - 10)).toPrecision(1 + Math.floor(Math.random() * 17)));
const total = Number(process.env.JCS_COUNT ?? 1_000_000);
let batch = [...edge];
let checked = 0;
function flush() {
  const bits = batch.map(bitsOf);
  const got = c.call("jcs_numbers", { bits });
  if (!got.ok) throw new Error(JSON.stringify(got));
  for (let i = 0; i < batch.length; i++) {
    const x = batch[i];
    const want = Number.isFinite(x) ? JSON.stringify(x) : null;
    checked += 1;
    if (got.out[i] !== want) mismatch("jcs/numbers", { bits: bits[i], got: got.out[i], want });
  }
  batch = [];
}
for (let i = 0; i < total; i++) {
  const r = i % 3;
  let x = r === 0 ? randomBits() : r === 1 ? randomDecimal() : Math.floor(Math.random() * 2 ** 53) * (Math.random() < 0.5 ? -1 : 1);
  if (!Number.isFinite(x)) continue;
  batch.push(x);
  if (batch.length === 5000) flush();
}
flush();
note("jcs/numbers", "checked", checked);

// --- Trap recovery and memory -----------------------------------------------------------------
{
  const h = resilient(module);
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const msg = randomBytes(200);
  const input = { key: { x: jwk.x, y: jwk.y }, msg: b64u(msg), sig: b64u(sign("sha256", msg, privateKey)) };
  const before = h.call("p256", input).ok;
  const trapped = h.call("trap", {});
  const after = h.call("p256", input).ok;
  report.sections.trap = { before, trapped, after, rebuilt: h.rebuilt };
  if (!(before && after && trapped.reason === "trap" && h.rebuilt === 1)) mismatch("trap", report.sections.trap);

  const mem = { start: h.memoryBytes() };
  const big = b64u(randomBytes(3 * 1024 * 1024)); // 4 MiB of base64url
  for (let i = 0; i < 200; i++) {
    h.call("p256", { ...input, msg: big });
    if (i === 0) mem.after_first_large = h.memoryBytes();
  }
  mem.after_200_large = h.memoryBytes();
  for (let i = 0; i < 2000; i++) h.call("p256", input);
  mem.after_2000_small = h.memoryBytes();
  const tooLarge = h.call("p256", { ...input, msg: b64u(randomBytes(4 * 1024 * 1024)) });
  mem.over_limit_answer = tooLarge.reason;
  report.sections.memory = mem;
}

report.failures = failures;
console.log(JSON.stringify(report, null, 2));
process.exit(failures ? 1 : 0);
