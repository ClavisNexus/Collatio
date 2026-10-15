// Records calls and the exact answer bytes from the JS host, for other hosts to replay (§18.10 item 5).
//   node spike/host/record.mjs > spike/vectors/answers.jsonl
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { instantiate } from "./collatio.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const module = new WebAssembly.Module(readFileSync(join(here, "../out/collatio_spike.wasm")));
const c = instantiate(module);
const e = c.exports;
const enc = new TextEncoder();
const dec = new TextDecoder();
const hex2b64u = (h) => Buffer.from(h, "hex").toString("base64url");

function rawAnswer(text) {
  const bytes = enc.encode(text);
  const p = e.alloc(bytes.length);
  new Uint8Array(e.memory.buffer, p, bytes.length).set(bytes);
  const out = e.verify(p, bytes.length);
  e.free(p, bytes.length);
  const len = new DataView(e.memory.buffer).getUint32(out, true);
  const answer = dec.decode(new Uint8Array(e.memory.buffer, out + 4, len));
  e.free(out, 4 + len);
  return answer;
}
function emit(call) {
  const text = JSON.stringify(call);
  process.stdout.write(JSON.stringify({ call: text, answer: rawAnswer(text) }) + "\n");
}

for (const call of Object.values(JSON.parse(readFileSync(join(here, "../vectors/bench.json"), "utf8")))) emit(call);
const wdir = join(here, "../vectors/wycheproof");
for (const file of readdirSync(wdir).filter((f) => f.endsWith(".json")).sort()) {
  const j = JSON.parse(readFileSync(join(wdir, file), "utf8"));
  for (const g of j.testGroups) {
    for (const t of g.tests) {
      if (file.startsWith("rsa_signature")) {
        const k = g.publicKeyJwk ?? g.keyJwk;
        emit({ op: "rsa", input: { n: k.n, e: k.e, msg: hex2b64u(t.msg), sig: hex2b64u(t.sig), hash: g.sha.replace("SHA-", "sha") } });
      } else {
        const pad = (h) => h.replace(/^00/, "").padStart(64, "0");
        emit({ op: "p256", input: { key: { x: hex2b64u(pad(g.publicKey.wx)), y: hex2b64u(pad(g.publicKey.wy)) }, msg: hex2b64u(t.msg), sig: hex2b64u(t.sig), format: file.includes("p1363") ? "raw" : "der" } });
      }
    }
  }
}
const dv = new DataView(new ArrayBuffer(8));
for (let b = 0; b < 20; b++) {
  const bits = [];
  for (let i = 0; i < 5000; i++) {
    dv.setUint32(0, (Math.random() * 2 ** 32) >>> 0);
    dv.setUint32(4, (Math.random() * 2 ** 32) >>> 0);
    bits.push(dv.getBigUint64(0).toString(16).padStart(16, "0"));
  }
  emit({ op: "jcs_numbers", input: { bits } });
}
emit({ op: "nope", input: {} });
emit({ op: "p256", input: { key: {} } });
