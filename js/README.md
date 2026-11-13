# @clavis.nexus/collatio

The Collatio verifier for [Clavis](https://clavis.nexus) evidence: one WebAssembly module and a JavaScript host. The module takes no imports and keeps no clock. Pass the evidence, the trust root and the time.

This package ships `collatio.wasm` `sha256:wlXFoRaJ0patHXsdAwx3NRUqQB52gosZ77i2aQtf_HI`.

## Install

```bash
npm install @clavis.nexus/collatio
```

Requires Node.js 24 or newer. Where a build step compiles the module ahead of time (Cloudflare Workers), pass that compiled module to `Collatio.load`.

## Use

```js
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { Collatio, moduleDigest } from "@clavis.nexus/collatio";

const require = createRequire(import.meta.url);
const bytes = new Uint8Array(await readFile(require.resolve("@clavis.nexus/collatio/collatio.wasm")));
const digest = await moduleDigest(bytes);
const collatio = await Collatio.fromBytes([{ bytes, digest }]);
const answer = await collatio.call(input);
```

`input` is the outer JSON object. Evidence inside it stays the string that was received. The operations and the reasons are in `ABI.md` in the [repository](https://github.com/clavisnexus/collatio).

## License

MIT. The Rust crates linked into `collatio.wasm` are listed in `THIRD-PARTY-NOTICES.md`.
