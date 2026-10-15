#!/usr/bin/env node
// Writes the small modules the host conformance tests run (conformance/modules/*.wasm).
//
// Each is a hand-assembled WebAssembly 1.0 module with the collatio-abi@1 exports. `verify`
// answers a fixed `{"ok":true,"stub":true}`, except that it traps when the input starts with
// `T`. The variants differ in one point each: the ABI version, a missing export, or memory that
// grows on every call.
//
//   node tools/conformance-modules.mjs

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "conformance", "modules");

const uleb = (n) => {
  const bytes = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    bytes.push(b);
  } while (n !== 0);
  return bytes;
};
const sleb = (n) => {
  const bytes = [];
  for (;;) {
    const b = n & 0x7f;
    n >>= 7;
    if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) {
      bytes.push(b);
      return bytes;
    }
    bytes.push(b | 0x80);
  }
};
const vec = (items) => [...uleb(items.length), ...items.flat()];
const name = (s) => vec([...Buffer.from(s)]);
const section = (id, body) => [id, ...uleb(body.length), ...body];

const I32 = 0x7f;
const functype = (params, results) => [0x60, ...vec(params), ...vec(results)];
const end = 0x0b;

function module({ version = 1, exports = ["memory", "abi_version", "alloc", "free", "verify"], growPages = 0 }) {
  const answer = Buffer.from('{"ok":true,"stub":true}');
  const data = [...uleb32le(answer.length), ...answer];
  const types = [functype([], [I32]), functype([I32], [I32]), functype([I32, I32], []), functype([I32, I32], [I32])];
  const bodies = [
    [0x41, ...sleb(version), end], // abi_version
    [0x41, ...sleb(1024), end], // alloc: one fixed buffer
    [end], // free
    [
      ...(growPages ? [0x41, ...sleb(growPages), 0x40, 0x00, 0x1a] : []), // memory.grow, drop
      0x20, 0x00, 0x2d, 0x00, 0x00, // local.get 0; i32.load8_u
      0x41, ...sleb(0x54), 0x46, // i32.const 'T'; i32.eq
      0x04, 0x40, 0x00, end, // if: unreachable
      0x41, 0x00, end, // the answer at 0
    ],
  ];
  const index = { abi_version: 0, alloc: 1, free: 2, verify: 3 };
  const exportEntries = exports.map((e) => (e === "memory" ? [...name(e), 0x02, 0x00] : [...name(e), 0x00, ...uleb(index[e])]));
  const bytes = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, vec(types)),
    ...section(3, vec([[0], [1], [2], [3]])),
    ...section(5, vec([[0x00, ...uleb(1)]])),
    ...section(7, vec(exportEntries)),
    ...section(10, vec(bodies.map((b) => [...uleb(b.length + 1), 0x00, ...b]))),
    ...section(11, vec([[0x00, 0x41, 0x00, end, ...vec([...data])]])),
  ];
  return Buffer.from(bytes);
}

function uleb32le(n) {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

mkdirSync(out, { recursive: true });
const modules = {
  "stub.wasm": module({}),
  "abi2.wasm": module({ version: 2 }),
  "no-abi-version.wasm": module({ exports: ["memory", "alloc", "free", "verify"] }),
  "grow.wasm": module({ growPages: 16 }),
};
for (const [file, bytes] of Object.entries(modules)) {
  await WebAssembly.compile(bytes); // fails here if the assembly is wrong
  writeFileSync(join(out, file), bytes);
  console.log(`${file} ${bytes.length} bytes`);
}
