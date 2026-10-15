// Minimal JS host for collatio-abi@1 (genesis.md §18.3). Works in Node and Workers.
// The module has no imports, so instantiation takes an empty import object.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function instantiate(module) {
  const instance = new WebAssembly.Instance(module, {});
  const e = instance.exports;
  if (e.abi_version() !== 1) throw new Error(`abi_version ${e.abi_version()}`);
  return {
    exports: e,
    memoryBytes: () => e.memory.buffer.byteLength,
    callRaw(bytes) {
      const p = e.alloc(bytes.length);
      new Uint8Array(e.memory.buffer, p, bytes.length).set(bytes);
      const out = e.verify(p, bytes.length);
      e.free(p, bytes.length);
      const len = new DataView(e.memory.buffer).getUint32(out, true);
      const text = decoder.decode(new Uint8Array(e.memory.buffer, out + 4, len));
      e.free(out, 4 + len);
      return JSON.parse(text);
    },
    call(op, input) {
      return this.callRaw(encoder.encode(JSON.stringify({ op, input })));
    },
  };
}

/** A host that rebuilds its instance after a trap (§18.7: a trapped instance is not reused). */
export function resilient(module) {
  let current = instantiate(module);
  let rebuilt = 0;
  return {
    get rebuilt() {
      return rebuilt;
    },
    memoryBytes: () => current.memoryBytes(),
    call(op, input) {
      try {
        return current.call(op, input);
      } catch (err) {
        if (!(err instanceof WebAssembly.RuntimeError)) throw err;
        current = instantiate(module);
        rebuilt += 1;
        return { ok: false, reason: "trap" };
      }
    },
  };
}
