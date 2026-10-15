// Writes N distinct copies of a verifier for the multi-verifier Worker (§18.10 item 9).
// Each copy gets a custom section `collatio-spike-copy` holding its index, so the bytes and
// hashes differ while behavior does not (custom sections are ignored by the engine).
//   node spike/worker/scripts/make-copies.mjs [count] [source.wasm]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const count = Number(process.argv[2] ?? 8);
const source = process.argv[3] ?? join(here, "../../out/collatio_spike.probe.wasm");
const base = readFileSync(source);
const outDir = join(here, "../gen");
mkdirSync(outDir, { recursive: true });

function leb128(n) {
  const out = [];
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n) byte |= 0x80;
    out.push(byte);
  } while (n);
  return out;
}

for (let i = 0; i < count; i++) {
  const name = Buffer.from("collatio-spike-copy");
  const payload = Buffer.from(String(i));
  const body = Buffer.concat([Buffer.from(leb128(name.length)), name, payload]);
  const section = Buffer.concat([Buffer.from([0]), Buffer.from(leb128(body.length)), body]);
  writeFileSync(join(outDir, `collatio_spike_${i}.wasm`), Buffer.concat([base, section]));
}
console.log(`${count} copies of ${source} (${base.length} bytes each) in ${outDir}`);
