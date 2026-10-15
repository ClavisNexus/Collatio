// Host conformance (ABI.md §Hosts) and the genesis vectors through the JavaScript host.
// The real module is out/collatio.wasm (./build.sh), or COLLATIO_WASM.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Collatio, CollatioError } from "../collatio.mjs";

const repo = new URL("../../", import.meta.url);
const readJson = (path) => JSON.parse(readFileSync(new URL(path, repo), "utf8"));
const realModule = await WebAssembly.compile(readFileSync(process.env.COLLATIO_WASM ?? new URL("out/collatio.wasm", repo)));

function jcs(v) {
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (v !== null && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

/** Every member the vector states must be in the answer, the same. */
function assertAnswer(got, want, where) {
  for (const [k, v] of Object.entries(want)) assert.equal(jcs(got[k]), jcs(v), `${where}: ${k}`);
}

async function hostFor(scenario) {
  const modules = scenario.modules.map((m) =>
    m.file === "collatio"
      ? { digest: m.digest, module: realModule }
      : { digest: `stub:${m.file}`, module: new WebAssembly.Module(readFileSync(new URL(`conformance/modules/${m.file}`, repo))) },
  );
  return Collatio.load(modules, scenario.max_memory ? { maxMemory: scenario.max_memory } : {});
}

const { scenarios } = readJson("conformance/hosts-1.json");
for (const scenario of scenarios) {
  test(`host: ${scenario.name}`, async () => {
    if (scenario.load_error) {
      await assert.rejects(hostFor(scenario), (e) => e instanceof CollatioError && e.reason === scenario.load_error);
      return;
    }
    const host = await hostFor(scenario);
    for (const [i, c] of scenario.calls.entries()) {
      const got = await host.call(c.raw ?? c.input);
      assertAnswer(got, c.answer, `call ${i}`);
      for (const k of c.absent ?? []) assert.ok(!(k in got), `call ${i}: ${k} should be absent`);
    }
    if (scenario.instantiations !== undefined) assert.equal(host.instantiations, scenario.instantiations);
  });
}

test("host: the genesis vectors give the same answers", async () => {
  const { cases } = readJson("vectors/genesis/ops-1.json");
  // The vectors' catalog lists the test verifier digest; declare the real module under it.
  const verifier = readJson("conformance/hosts-1.json").scenarios.find((s) => s.name === "a receipt on the module it names")
    .modules[0].digest;
  const host = await Collatio.load([{ digest: verifier, module: realModule }]);
  for (const c of cases) assertAnswer(await host.call(c.input), c.answer, c.name);
});

test("host: fromBytes computes the digest and refuses a wrong declared one", async () => {
  const bytes = readFileSync(new URL("conformance/modules/stub.wasm", repo));
  const host = await Collatio.fromBytes([bytes]);
  assert.match(host.digests[0], /^sha256:[A-Za-z0-9_-]{43}$/);
  await assert.rejects(Collatio.fromBytes([{ bytes, digest: "sha256:x" }]), (e) => e.reason === "digest_mismatch");
});
