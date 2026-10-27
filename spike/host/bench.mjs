// Timing in Node (V8), as the reference for the Workers numbers (item 2 of spike/README.md).
//   node spike/host/bench.mjs [wasm]
// Writes vectors/bench.json on first run (fixed inputs reused by the Worker and Go hosts).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { instantiate } from "./collatio.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const benchPath = join(here, "../vectors/bench.json");
const b64u = (b) => Buffer.from(b).toString("base64url");

if (!existsSync(benchPath)) {
  const calls = {};
  {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const msg = randomBytes(37 + 32); // authenticatorData (no extensions) || SHA-256(clientDataJSON)
    calls.p256 = { op: "p256", input: { key: { x: jwk.x, y: jwk.y }, msg: b64u(msg), sig: b64u(sign("sha256", msg, privateKey)), format: "der" } };
  }
  {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const msg = randomBytes(160); // a signed note body
    calls.ed25519 = { op: "ed25519", input: { key: publicKey.export({ format: "jwk" }).x, msg: b64u(msg), sig: b64u(sign(null, msg, privateKey)) } };
  }
  for (const bits of [2048, 4096]) {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
    const jwk = publicKey.export({ format: "jwk" });
    const msg = randomBytes(120); // CMS signed attributes
    calls[`rsa${bits}`] = { op: "rsa", input: { n: jwk.n, e: jwk.e, msg: b64u(msg), sig: b64u(sign("sha256", msg, privateKey)), hash: "sha256" } };
  }
  writeFileSync(benchPath, JSON.stringify(calls, null, 2) + "\n");
}

const calls = JSON.parse(readFileSync(benchPath, "utf8"));
const wasmPath = process.argv[2] ?? join(here, "../out/collatio_spike.wasm");
const bytes = readFileSync(wasmPath);

let t = performance.now();
const module = new WebAssembly.Module(bytes);
const compileMs = performance.now() - t;
t = performance.now();
const c = instantiate(module);
const instantiateMs = performance.now() - t;

const out = { wasm: wasmPath, bytes: bytes.length, compile_ms: +compileMs.toFixed(2), instantiate_ms: +instantiateMs.toFixed(3), per_call_ms: {} };
for (const [name, call] of Object.entries(calls)) {
  const first = performance.now();
  if (!c.call(call.op, call.input).ok) throw new Error(`${name} failed`);
  const firstMs = performance.now() - first;
  const times = name.startsWith("rsa4096") ? 50 : 200;
  const r0 = performance.now();
  const r = c.call("repeat", { times, call });
  const r1 = performance.now();
  if (r.passed !== times) throw new Error(`${name} repeat failed`);
  out.per_call_ms[name] = { first: +firstMs.toFixed(3), steady: +((r1 - r0) / times).toFixed(4) };
}
console.log(JSON.stringify(out, null, 2));
