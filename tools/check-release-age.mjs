#!/usr/bin/env node
// Every crate in Cargo.lock from crates.io must be published at least MIN_DAYS ago and not yanked.
//   node tools/check-release-age.mjs [min-days]
import { readFileSync } from "node:fs";

const MIN_DAYS = Number(process.argv[2] ?? 14);
const lock = readFileSync(new URL("../Cargo.lock", import.meta.url), "utf8");
const pkgs = [...lock.matchAll(/\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\nsource = "registry/g)].map((m) => [m[1], m[2]]);
let bad = 0;
for (const [name, version] of pkgs) {
  const res = await fetch(`https://crates.io/api/v1/crates/${name}/${version}`, { headers: { "user-agent": "collatio-release-age-check" } });
  const v = (await res.json()).version;
  const days = (Date.now() - Date.parse(v.created_at)) / 864e5;
  const problem = v.yanked ? "yanked" : days < MIN_DAYS ? `${Math.floor(days)} days old` : "";
  if (problem) bad += 1;
  console.log(`${problem ? "✗" : "✓"} ${name} ${version} ${v.created_at.slice(0, 10)}${problem ? ` (${problem})` : ""}`);
}
if (bad) {
  console.error(`${bad} crate(s) below the ${MIN_DAYS}-day minimum or yanked`);
  process.exit(1);
}
