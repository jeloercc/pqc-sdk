---
'@pqc-sdk/core': minor
---

Streaming encryption (`docs/proposals/streaming-encryption.md`) is now public: `pqc.encryptStream`/`pqc.decryptStream` for arbitrarily large payloads without holding them fully in memory, plus `pqc.encryptWebStream`/`pqc.decryptWebStream` (thin `TransformStream` adapters for `pipeThrough`/`pipeTo` pipelines) — both ML-KEM-768 and X-Wing supported from day one. New `pqcenc` envelope version bytes `0x03` (ml-kem-768 streaming) and `0x04` (x-wing streaming), additive alongside the existing v1/v2 one-shot envelopes, which are byte-for-byte unchanged.

`pqc.decryptStream` has an incremental-release property one-shot `pqc.decrypt` does not: it yields each plaintext chunk as soon as that chunk authenticates, so a truncated or tampered stream can yield genuine prefix chunks before throwing. Only the async iterable completing without throwing means the full plaintext is authentic and complete — see the JSDoc on `decryptStream` for the full explanation and a worked example of handling this correctly.

Verified end-to-end with real large-file roundtrips on Node (`fs` streams via `Readable.toWeb`/`Writable.toWeb`), Deno (native `Deno.FsFile` streams), and Cloudflare Workers (in-memory, workerd's `TransformStream`) — see `docs/compatibility.md`. Hermes and React Native stay ⏳, tracked by issue #45.
