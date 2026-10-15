// Summarizes a measure.sh run: CPU time per verification from tail events (cpuTime),
// as (median CPU at times=101 − median at times=1) / 100 / verifications per case.
//   node spike/worker/analyze.mjs spike/results/<run>
import { readFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
const PARTS = { p256: 1, ed25519: 1, rsa2048: 1, rsa4096: 1, receipt: 3, bundle_tsa: 6 };

// `wrangler tail --format json` prints one JSON value per event, possibly across lines.
function parseConcatenated(text) {
  const values = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        try {
          values.push(JSON.parse(text.slice(start, i + 1)));
        } catch {}
        start = -1;
      }
    }
  }
  return values;
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)] : null;
};

const events = parseConcatenated(readFileSync(join(dir, "tail.jsonl"), "utf8"));
const byKey = new Map();
let withCpu = 0;
for (const e of events) {
  const url = e?.event?.request?.url;
  if (!url) continue;
  const u = new URL(url);
  if (u.pathname !== "/run") continue;
  const cpu = e.cpuTime ?? e.cpu_time ?? null;
  const wall = e.wallTime ?? e.wall_time ?? null;
  if (cpu != null) withCpu += 1;
  const key = `${u.searchParams.get("case")}:${u.searchParams.get("times")}`;
  if (!byKey.has(key)) byKey.set(key, { cpu: [], wall: [] });
  if (cpu != null) byKey.get(key).cpu.push(cpu);
  if (wall != null) byKey.get(key).wall.push(wall);
}

const perCase = {};
for (const [name, parts] of Object.entries(PARTS)) {
  const one = byKey.get(`${name}:1`);
  const many = byKey.get(`${name}:101`);
  if (!one || !many) continue;
  const c1 = median(one.cpu);
  const c101 = median(many.cpu);
  perCase[name] = {
    cpu_ms_times1_median: c1,
    cpu_ms_times101_median: c101,
    cpu_ms_per_verification: c1 != null && c101 != null ? +((c101 - c1) / 100 / parts).toFixed(4) : null,
    cpu_ms_per_case: c1 != null && c101 != null ? +((c101 - c1) / 100).toFixed(4) : null,
    samples: one.cpu.length + many.cpu.length,
  };
}

const read = (f) => {
  try {
    return JSON.parse(readFileSync(join(dir, f), "utf8"));
  } catch {
    return null;
  }
};
console.log(
  JSON.stringify(
    {
      tail_events: events.length,
      events_with_cpu_time: withCpu,
      first_request: read("first.json"),
      per_case: perCase,
      trap: read("trap.json"),
      memory: read("memory.json"),
      info: read("info.json"),
      note: withCpu ? undefined : "tail events had no cpuTime; read CPU time per request from Workers Logs (observability is on) instead",
    },
    null,
    2,
  ),
);
