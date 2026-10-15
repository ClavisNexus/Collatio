/** A refusal before any answer: the module cannot be used (`unsupported_abi`, `digest_mismatch`). */
export declare class CollatioError extends Error {
  readonly reason: string;
  constructor(reason: string);
}

/** `sha256:` + Base64URL of the module bytes. */
export declare function moduleDigest(bytes: BufferSource): Promise<string>;

/** An answer: `{ ok: true, … }` with what the module established, or `{ ok: false, reason }`. */
export type Answer = { ok: true; [member: string]: unknown } | { ok: false; reason: string };

export type CollatioOptions = {
  /** Replace an instance whose memory grows above this many bytes (default 64 MiB). */
  maxMemory?: number;
};

export declare class Collatio {
  constructor(options?: CollatioOptions);
  /** Compiles and loads modules; the first is the default. A declared digest must match. */
  static fromBytes(
    list: ReadonlyArray<Uint8Array | { bytes: Uint8Array; digest?: string }>,
    options?: CollatioOptions,
  ): Promise<Collatio>;
  /** Loads compiled modules with the digests a build step computed. The first is the default. */
  static load(
    modules: ReadonlyArray<{ digest: string; module: WebAssembly.Module }>,
    options?: CollatioOptions,
  ): Promise<Collatio>;
  /** How many instances were made. */
  readonly instantiations: number;
  /** The digests of the loaded modules, default first. */
  readonly digests: readonly string[];
  /** One call (ABI.md §Hosts): picks the module, follows revoked verifiers, marks a stale catalog. */
  call(input: object | string): Promise<Answer>;
  /** One call on the module with `digest`, without routing. */
  run(digest: string, input: object | string): Promise<Answer>;
}
