#!/usr/bin/env node
// Copies the reference collatio.wasm and LICENSE into js/ so `npm pack` / `npm publish` ship them.
// The bytes are the matching pair from repro/run.sh. A native build is not the released module.
import { createHash } from "node:crypto";
import { copyFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const digest = (bytes) => createHash("sha256").update(bytes).digest("base64url").replace(/=+$/, "");

let first, second;
try {
  first = readFileSync(join(root, "repro", "out-1", "collatio.wasm"));
  second = readFileSync(join(root, "repro", "out-2", "collatio.wasm"));
} catch {
  console.error("repro/out-1 and repro/out-2 are missing. Run repro/run.sh before packing.");
  process.exit(1);
}
const a = digest(first);
const b = digest(second);
if (a !== b) {
  console.error(`reference builds differ:\n  ${a}\n  ${b}`);
  process.exit(1);
}
copyFileSync(join(root, "repro", "out-1", "collatio.wasm"), join(root, "js", "collatio.wasm"));
copyFileSync(join(root, "LICENSE"), join(root, "js", "LICENSE"));
console.log(`collatio.wasm sha256:${a}`);
