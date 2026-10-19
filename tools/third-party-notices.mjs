#!/usr/bin/env node
// Writes THIRD-PARTY-NOTICES.md (repo root and js/) for the crates compiled into collatio.wasm.
// Each crate is listed with the license it is used under here and that license's text from the crate source.
// Needs the crate sources: run `cargo fetch --target wasm32v1-none` first (same CARGO_HOME).
//   node tools/third-party-notices.mjs
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const meta = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--filter-platform", "wasm32v1-none"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  }),
);
const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));

// Normal (runtime) dependencies only: build scripts and dev-dependencies do not end up in the binary.
const seen = new Set();
const stack = [...meta.workspace_members];
while (stack.length) {
  const id = stack.pop();
  if (seen.has(id)) continue;
  seen.add(id);
  for (const d of nodes.get(id).deps) if (d.dep_kinds.some((k) => k.kind === null)) stack.push(d.pkg);
}
const crates = [...seen]
  .map((id) => pkgs.get(id))
  .filter((p) => !meta.workspace_members.includes(p.id))
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

const CANDIDATES = {
  MIT: { files: ["LICENSE-MIT", "LICENSE-MIT.md", "LICENSE-MIT.txt", "LICENSE", "LICENSE.md", "LICENSE.txt"], mark: "Permission is hereby granted" },
  "BSL-1.0": { files: ["LICENSE-BOOST", "LICENSE-BSL", "LICENSE"], mark: "Boost Software License" },
  "BSD-3-Clause": { files: ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE-BSD"], mark: "Redistribution and use" },
};

/** The license used here: MIT where offered, else BSL-1.0, else BSD-3-Clause. */
function chosen(expr) {
  const parts = expr.replaceAll("/", " OR ").split("OR").map((s) => s.trim());
  return ["MIT", "BSL-1.0", "BSD-3-Clause"].find((l) => parts.includes(l)) ?? null;
}

const sections = [];
const missing = [];
for (const p of crates) {
  const license = chosen(p.license ?? "");
  const dir = dirname(p.manifest_path);
  const spec = license ? CANDIDATES[license] : null;
  const file = spec?.files.find((f) => existsSync(join(dir, f)) && readFileSync(join(dir, f), "utf8").includes(spec.mark));
  if (!file) {
    missing.push(`${p.name} ${p.version} (${p.license}; files: ${readdirSync(dir).join(", ")})`);
    continue;
  }
  const text = readFileSync(join(dir, file), "utf8").trim();
  sections.push(`\n## ${p.name} ${p.version}\n\nLicense: ${p.license} (used under ${license})\n\n\`\`\`text\n${text}\n\`\`\`\n`);
}
if (missing.length) {
  console.error(`no license text found for:\n${missing.join("\n")}`);
  process.exit(1);
}
const doc = [
  "# Third-party notices for collatio.wasm\n",
  "\ncollatio.wasm is built from the Collatio source (MIT, see LICENSE) together with the Rust crates below. Each crate is listed with the license under which it is used here, followed by that license's text with the crate's copyright notice. Generated from Cargo.lock by `node tools/third-party-notices.mjs`; do not edit by hand.\n",
  ...sections,
].join("");
writeFileSync(join(root, "THIRD-PARTY-NOTICES.md"), doc);
writeFileSync(join(root, "js", "THIRD-PARTY-NOTICES.md"), doc);
console.log(`${crates.length} crates → THIRD-PARTY-NOTICES.md, js/THIRD-PARTY-NOTICES.md`);
