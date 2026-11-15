// Spike Worker for items 1–4 of spike/README.md. Not bound to any route, resource or key.
//   GET /info                    abi_version, module bytes, memory
//   GET /run?case=<c>&times=<n>  runs one case n times inside the verifier (CPU: compare n=1 and n=k)
//   GET /trap                    traps, then answers again from a rebuilt instance
//   GET /memory                  50 large inputs, then reports linear memory
// Cases: p256, ed25519, rsa2048, rsa4096, receipt (p256 + p256 + ed25519), bundle_tsa (receipt + rsa4096 x2 + rsa2048).
import verifier from "../../out/collatio_spike.wasm";
import bench from "../../vectors/bench.json";
import { resilient } from "../../host/collatio.mjs";

const COMPOSITES = {
  receipt: ["p256", "p256", "ed25519"],
  bundle_tsa: ["p256", "p256", "ed25519", "rsa4096", "rsa4096", "rsa2048"],
};

let host;
const startedAt = Date.now();
let requests = 0;

function getHost() {
  host ??= resilient(verifier);
  return host;
}

function runCase(h, name, times) {
  const parts = COMPOSITES[name] ?? [name];
  let passed = 0;
  for (const part of parts) {
    const call = bench[part];
    if (!call) throw new Error(`unknown case ${part}`);
    const r = h.call("repeat", { times, call });
    if (r.ok) passed += r.passed;
  }
  return { expected: parts.length * times, passed };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    requests += 1;
    const isolate = { age_ms: Date.now() - startedAt, requests };
    const h = getHost();
    switch (url.pathname) {
      case "/info":
        return json({ isolate, memory: h.memoryBytes(), rebuilt: h.rebuilt });
      case "/run": {
        const name = url.searchParams.get("case") ?? "p256";
        const times = Math.min(Number(url.searchParams.get("times") ?? 1), 1000);
        const r = runCase(h, name, times);
        console.log(JSON.stringify({ label: `run:${name}:${times}`, ...r }));
        return json({ case: name, times, ...r, isolate, memory: h.memoryBytes() });
      }
      case "/trap": {
        const before = h.call(bench.p256.op, bench.p256.input).ok;
        const trapped = h.call("trap", {});
        const after = h.call(bench.p256.op, bench.p256.input).ok;
        return json({ before, trapped, after, rebuilt: h.rebuilt, isolate });
      }
      case "/memory": {
        const start = h.memoryBytes();
        const big = "A".repeat(3 * 1024 * 1024);
        for (let i = 0; i < 50; i++) h.call("p256", { ...bench.p256.input, msg: big });
        const afterLarge = h.memoryBytes();
        const small = runCase(h, "p256", 100);
        return json({ start, after_50_large: afterLarge, after_small: h.memoryBytes(), small, isolate });
      }
      default:
        return json({ error: "not_found" }, 404);
    }
  },
};
