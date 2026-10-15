# collatio-abi@1

How a host runs `collatio.wasm`. The JavaScript and Go hosts implement this page separately, so it is the contract between them and the module. A change that breaks it is `collatio-abi@2`, with a new `abi_version`, and hosts refuse a module whose version they do not know.

## Module

- WebAssembly 1.0 with mutable globals (`wasm32v1-none`). No imports: instantiate with an empty import object.
- Exports:

| Export | Type | |
|---|---|---|
| `memory` | memory | Linear memory. It grows and never shrinks. |
| `abi_version` | `() -> i32` | Returns `1`. A function, not a global: Rust exports a `static` as its address. |
| `alloc` | `(len: i32) -> i32` | Returns a pointer to `len` writable bytes, or 0 when memory is exhausted. |
| `free` | `(ptr: i32, len: i32)` | Returns a buffer from `alloc` or from `verify`. |
| `verify` | `(in_ptr: i32, in_len: i32) -> i32` | Runs one call. Returns a pointer to the answer. |

## A call

1. `p = alloc(n)`; write the n bytes of the input (UTF-8 JSON) at `p`.
2. `out = verify(p, n)`; then `free(p, n)`.
3. Read 4 bytes at `out` as a little-endian unsigned length `m`; the answer is the m bytes at `out + 4` (UTF-8 JSON).
4. `free(out, 4 + m)`.

The module is synchronous and keeps no state between calls other than its allocator. One instance serves one call at a time.

## Trap

`verify` traps instead of answering only on a bug or when memory is exhausted. After a trap the instance is discarded; the host instantiates a new one from the same compiled module before the next call. Hosts also replace an instance whose memory has grown past their limit.

## Input

A JSON object built by the host, at most 4 MiB:

```json
{ "op": "<operation>", "now": 1791747761, "evidence": "<the evidence as received, as a JSON string>", "trust": { … } }
```

Evidence, trust documents and registries are passed as JSON strings holding the bytes as received; the module reads them again with its strict reader. Which members an operation reads is listed with the operation.

## Answer

Canonical JSON (RFC 8785). Either `{"ok":true, …}` with what the module established, or `{"ok":false,"reason":"<reason>"}`. Hosts read results only from the answer, never by parsing the evidence themselves.

## Operations

No operation is available yet; every `op` answers `unknown_op`. The operations of the first release are `proof`, `receipt`, `app_receipt`, `mandate_history`, `chain`, `trust`, `ledger_note`, `inclusion`, `consistency` and `bundle`.

## Reasons

Reasons are only added, never renamed or reused.

| Reason | |
|---|---|
| `input_too_large` | The input is larger than 4 MiB. |
| `input_malformed` | The input is not a JSON object with a string `op`. |
| `unknown_op` | No operation by that name. |
| `json_syntax` | A document is not UTF-8 or not one JSON value. |
| `json_duplicate_key` | A document repeats a key in an object. |
| `json_lone_surrogate` | A document has a `\u` escape that leaves a lone surrogate. |
| `json_non_finite` | A document has a number that reads as infinity. |
| `json_too_deep` | A document nests arrays and objects more than 64 deep. |
