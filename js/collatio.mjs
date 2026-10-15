// The JavaScript host for collatio.wasm (ABI.md): instances, traps, which module may answer,
// and catalog freshness. Evidence goes in as the strings received; results come from the answer.

const ABI_VERSION = 1;
const DEFAULT_MAX_MEMORY = 64 * 1024 * 1024;
const STALE_AFTER = 7 * 86400;
const RECEIPT_OPS = new Set(["receipt", "app_receipt"]);
const TRUST_CACHE = 16;
const EXPORTS = ["alloc", "free", "verify", "abi_version"];

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** A refusal before any answer: the module cannot be used. */
export class CollatioError extends Error {
  /** @param {string} reason */
  constructor(reason) {
    super(reason);
    this.name = "CollatioError";
    this.reason = reason;
  }
}

function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** `sha256:` + Base64URL of the module bytes. */
export async function moduleDigest(bytes) {
  return `sha256:${b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)))}`;
}

const refused = (reason) => ({ ok: false, reason });

export class Collatio {
  #slots = [];
  #maxMemory;
  #trustCache = new Map();
  #instantiations = 0;

  /** @param {{ maxMemory?: number }} [options] */
  constructor(options = {}) {
    this.#maxMemory = options.maxMemory ?? DEFAULT_MAX_MEMORY;
  }

  /**
   * Compiles module bytes and loads them; the first is the default. An entry may declare its
   * digest, which must then match the bytes.
   */
  static async fromBytes(list, options) {
    const modules = [];
    for (const item of list) {
      const bytes = item instanceof Uint8Array ? item : item.bytes;
      const digest = await moduleDigest(bytes);
      if (!(item instanceof Uint8Array) && item.digest !== undefined && item.digest !== digest) {
        throw new CollatioError("digest_mismatch");
      }
      modules.push({ digest, module: await WebAssembly.compile(bytes) });
    }
    return Collatio.load(modules, options);
  }

  /**
   * Loads compiled modules with their digests (where a build step compiled them, as on Cloudflare
   * Workers). The first is the default.
   */
  static async load(modules, options) {
    const c = new Collatio(options);
    for (const { digest, module } of modules) await c.#add(digest, module);
    return c;
  }

  /** How many instances were made (for tests and monitoring). */
  get instantiations() {
    return this.#instantiations;
  }

  /** The digests of the loaded modules, default first. */
  get digests() {
    return this.#slots.map((s) => s.digest);
  }

  async #add(digest, module) {
    const slot = { digest, module, instance: null };
    await this.#instantiate(slot);
    this.#slots.push(slot);
  }

  async #instantiate(slot) {
    const instance = await WebAssembly.instantiate(slot.module, {});
    this.#instantiations++;
    const x = instance.exports;
    if (!(x.memory instanceof WebAssembly.Memory) || EXPORTS.some((e) => typeof x[e] !== "function")) {
      throw new CollatioError("unsupported_abi");
    }
    if (x.abi_version() !== ABI_VERSION) throw new CollatioError("unsupported_abi");
    slot.instance = instance;
  }

  async #invoke(slot, bytes) {
    if (!slot.instance) await this.#instantiate(slot);
    const x = slot.instance.exports;
    let text;
    try {
      const p = x.alloc(bytes.length);
      if (p === 0) throw new WebAssembly.RuntimeError("alloc");
      new Uint8Array(x.memory.buffer, p, bytes.length).set(bytes);
      const out = x.verify(p, bytes.length);
      x.free(p, bytes.length);
      const len = new DataView(x.memory.buffer).getUint32(out, true);
      text = decoder.decode(new Uint8Array(x.memory.buffer, out + 4, len).slice());
      x.free(out, len + 4);
    } catch (e) {
      slot.instance = null;
      if (e instanceof WebAssembly.RuntimeError || e instanceof RangeError) return refused("verifier_trap");
      throw e;
    }
    if (x.memory.buffer.byteLength > this.#maxMemory) slot.instance = null;
    return JSON.parse(text);
  }

  /** Runs one call on the module with `digest`, with no routing. */
  async run(digest, input) {
    const slot = this.#slots.find((s) => s.digest === digest);
    if (!slot) return refused("verifier_unavailable");
    return this.#invoke(slot, encoder.encode(typeof input === "string" ? input : JSON.stringify(input)));
  }

  /** The verified trust answer and the modules that may answer under it. */
  async #trust(trust) {
    const key = JSON.stringify(trust);
    const hit = this.#trustCache.get(key);
    if (hit) return hit;
    const ask = (slot) => this.#invoke(slot, encoder.encode(JSON.stringify({ op: "trust", trust })));
    let answer = await ask(this.#slots[0]);
    if (answer.ok) {
      let runnable = this.#runnable(answer);
      if (runnable.length > 0 && runnable[0] !== this.#slots[0]) {
        answer = await ask(runnable[0]);
        if (answer.ok) runnable = this.#runnable(answer);
      }
      answer = { ...answer, runnable };
    }
    if (this.#trustCache.size >= TRUST_CACHE) this.#trustCache.delete(this.#trustCache.keys().next().value);
    this.#trustCache.set(key, answer);
    return answer;
  }

  #runnable(trustAnswer) {
    const listed = new Set(trustAnswer.verifiers.map((v) => v.digest));
    const revoked = new Set(trustAnswer.revoked.map((r) => r.verifier));
    return this.#slots.filter((s) => listed.has(s.digest) && !revoked.has(s.digest));
  }

  /**
   * Runs one call (ABI.md §Hosts). `input` is the outer input as an object, or its JSON text.
   * Evidence inside it stays as strings.
   */
  async call(input) {
    const text = typeof input === "string" ? input : JSON.stringify(input);
    const bytes = encoder.encode(text);
    let outer = input;
    if (typeof input === "string") {
      try {
        outer = JSON.parse(input);
      } catch {
        outer = null;
      }
    }
    if (outer === null || typeof outer !== "object" || outer.trust === undefined) {
      return this.#invoke(this.#slots[0], bytes);
    }
    const now = typeof outer.now === "number" ? outer.now : Math.floor(Date.now() / 1000);
    const trust = await this.#trust(outer.trust);
    if (!trust.ok) return { ok: false, reason: trust.reason };
    const [first] = trust.runnable;
    if (!first) return refused("verifier_unavailable");
    let answer = await this.#invoke(first, bytes);
    if (answer.ok && RECEIPT_OPS.has(outer.op)) {
      const target = this.#successor(answer.dimension.verifier, trust.revoked);
      if (target === null) return refused("verifier_unavailable");
      if (target !== first.digest) {
        const slot = trust.runnable.find((s) => s.digest === target);
        if (!slot) return refused("verifier_unavailable");
        answer = await this.#invoke(slot, bytes);
      }
      if (answer.ok) answer.verifier = target;
    }
    if (answer.ok && now - trust.issued_at > STALE_AFTER) answer.catalog_stale = true;
    return answer;
  }

  /** Follows revoked verifiers to their successor; null on a cycle. */
  #successor(digest, revoked) {
    const next = new Map(revoked.map((r) => [r.verifier, r.successor]));
    let d = digest;
    for (let i = 0; i <= next.size; i++) {
      if (!next.has(d)) return d;
      d = next.get(d);
    }
    return null;
  }
}
