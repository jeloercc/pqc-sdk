# Streaming large files

`pqc.encrypt`/`pqc.decrypt` hold the whole payload in memory — fine for
typical files, not for anything too large to comfortably fit as one
`Uint8Array`. `encryptStream`/`decryptStream` bound memory to roughly one
chunk (64 KiB by default) regardless of how large the file is, using the
chunked envelope described in
[docs/serialization-format.md §9](https://github.com/jeloercc/pqc-sdk/blob/main/docs/serialization-format.md#9-streaming-envelope-binary)
— age's STREAM construction, adopted verbatim, with both ML-KEM-768 and
X-Wing supported from day one.

::: tip Just using the CLI?
`pqc encrypt`/`pqc decrypt` already switch to streaming automatically above
8 MiB — nothing to opt into. This guide is for the SDK, when you need
streaming directly (a file larger than the CLI's threshold, piping through
an HTTP request body, etc.).
:::

## Basic usage: async iterables

The core primitive takes and returns `AsyncIterable<Uint8Array>` — plain
JavaScript, no host API dependency, so it works identically on every
supported runtime (see [compatibility](/compatibility) for which are
actually verified). Any async generator works as input, including a Node
`Readable` (already an `AsyncIterable<Buffer>` — `for await` works directly
on `fs.createReadStream(...)`):

```ts twoslash
import { createReadStream } from 'node:fs';
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();

const chunks: Uint8Array[] = [];
for await (const chunk of pqc.encryptStream(pair.publicKey, createReadStream('large-file.bin'))) {
  chunks.push(chunk);
}
```

For piping to a file or network destination, the Web Streams adapters below
are more convenient than collecting chunks yourself.

## Web Streams adapters (recommended for file/network I/O)

`encryptWebStream`/`decryptWebStream` wrap the core primitive as a
`TransformStream`, for `pipeThrough`/`pipeTo` pipelines. They add no crypto
of their own — pure plumbing around `encryptStream`/`decryptStream`.

```ts twoslash
import { createReadStream, createWriteStream } from 'node:fs';
import { Readable, Writable } from 'node:stream';
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();

await Readable.toWeb(createReadStream('large-file.bin'))
  .pipeThrough(pqc.encryptWebStream(pair.publicKey))
  .pipeTo(Writable.toWeb(createWriteStream('large-file.bin.enc')));
```

```ts twoslash
import { createReadStream, createWriteStream } from 'node:fs';
import { Readable, Writable } from 'node:stream';
import { pqc } from '@pqc-sdk/core';
declare const secretKey: import('@pqc-sdk/core').SecretKey<'ml-kem-768'>;
// ---cut---
await Readable.toWeb(createReadStream('large-file.bin.enc'))
  .pipeThrough(pqc.decryptWebStream(secretKey))
  .pipeTo(Writable.toWeb(createWriteStream('large-file.bin')));
```

Deno and Cloudflare Workers don't need the `Readable.toWeb`/`Writable.toWeb`
bridge — `Deno.FsFile`'s `.readable`/`.writable` and workerd's own streams
are already the same Web Streams types, so `pipeThrough`/`pipeTo` work
directly on them.

## The incremental-release property — read this before writing decrypted output

`decryptStream` (and `decryptWebStream`) yield each plaintext chunk **as
soon as that specific chunk authenticates**. Every chunk you receive is
genuinely authentic on its own — but that is a different, weaker guarantee
than one-shot `pqc.decrypt`, where the call returning already means the
_whole_ plaintext is authentic. Here:

- A truncated or tampered stream can — and for a stream cut off partway
  through, will — yield one or more genuine prefix chunks before throwing.
- **Only the stream finishing without throwing means the full plaintext is
  authentic and complete.** No individual chunk, and no chunk count, is
  proof of that.

This is structural to streaming/online AEAD (age has the same property),
not a shortcut this SDK took.

**What this means in practice:** if you write decrypted output to a file,
socket, or anywhere else observable, treat that output as provisional until
the write completes cleanly, and delete or discard it if the pipeline
throws — never treat a partially-written file as a short-but-valid result.
The CLI does exactly this: `pqc decrypt` deletes the partial output file the
moment a streamed decrypt fails.

```ts twoslash
import { pqc } from '@pqc-sdk/core';
declare const secretKey: import('@pqc-sdk/core').SecretKey<'ml-kem-768'>;
declare const ciphertextChunks: AsyncIterable<Uint8Array>;
// ---cut---
const provisional: Uint8Array[] = [];
try {
  for await (const chunk of pqc.decryptStream(secretKey, ciphertextChunks)) {
    provisional.push(chunk); // authentic on its own, not proof of completeness
  }
  // Reached only on clean completion — now the full plaintext is confirmed.
} catch (error) {
  // provisional is discarded here, never used as "the" plaintext.
  throw error;
}
```

## Choosing a chunk size

The default (`2^16`, 64 KiB) matches age's STREAM default and is the right
choice for almost everyone — it's what `.claude/rules`-style "safe defaults
always" means here. `chunkSize` is available as an advanced option
(`{ chunkSize: 1024 * 1024 }` for 1 MiB chunks, say) if you have a specific
reason to change it; it must be a power of two.

## Both KEMs, from day one

Streaming works with either KEM — `pqc.keys.generate()` (ML-KEM-768) or
`pqc.keys.generate({ algorithm: 'x-wing' })` — exactly like one-shot
`encrypt`/`decrypt`. See
[hybrid encryption explained](/guide/hybrid-encryption) for which to choose.

## Error handling

Same `PqcError` codes as one-shot decryption — `DECRYPTION_FAILED` for a
tampered or truncated stream, `INVALID_CIPHERTEXT` for a malformed or wrong
envelope. See [Encrypting files § Error handling](/guide/encrypt-files#error-handling).
