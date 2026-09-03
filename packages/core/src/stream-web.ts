import type { KemAlgorithm, PublicKey, SecretKey } from './types.js';
import { decryptStream, encryptStream, type StreamOptions } from './stream.js';

/**
 * Adapts a `ReadableStream<Uint8Array>` into the `AsyncIterable<Uint8Array>`
 * shape {@link encryptStream}/{@link decryptStream} take, using only
 * `getReader()` — no dependency on `ReadableStream`'s own async-iterator
 * support or `ReadableStream.from`, which differ across runtime versions.
 */
function fromReadableStream(stream: ReadableStream<Uint8Array>): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator]() {
      const reader = stream.getReader();
      return {
        async next(): Promise<IteratorResult<Uint8Array, void>> {
          const { value, done } = await reader.read();
          if (done) {
            return { value: undefined, done: true };
          }
          return { value, done: false };
        },
        async return(): Promise<IteratorResult<Uint8Array, void>> {
          await reader.cancel();
          return { value: undefined, done: true };
        },
      };
    },
  };
}

/** Wraps an `AsyncIterable<Uint8Array>` producer as a `ReadableStream<Uint8Array>`. */
function toReadableStream(source: AsyncIterable<Uint8Array>): ReadableStream<Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      // iterator.next()'s TReturn defaults to `any` on Symbol.asyncIterator's
      // signature; asserted away since only value/done are ever read.
      const { value, done } = (await iterator.next()) as IteratorResult<Uint8Array, void>;
      if (done) {
        controller.close();
        return;
      }
      controller.enqueue(value);
    },
    async cancel(reason) {
      await iterator.return?.(reason);
    },
  });
}

/**
 * Bridges an async-iterable transform (the core streaming primitive's
 * shape) into a `TransformStream`: an identity `TransformStream` supplies
 * the paired writable/readable the caller pipes into, its `readable` side
 * is consumed internally as the transform's input, and the transform's
 * output is wrapped back into a `ReadableStream` exposed as the result.
 * No independent crypto logic — purely plumbing around
 * {@link encryptStream}/{@link decryptStream}.
 */
function toTransformStream(
  transform: (input: AsyncIterable<Uint8Array>) => AsyncIterable<Uint8Array>,
): TransformStream<Uint8Array, Uint8Array> {
  const { readable: input, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const readable = toReadableStream(transform(fromReadableStream(input)));
  return { readable, writable };
}

/**
 * {@link encryptStream} as a Web Streams `TransformStream`, for
 * `pipeThrough`/`pipeTo` pipelines on runtimes with the WHATWG Streams API
 * (Node 18+, Deno, Cloudflare Workers — see `docs/compatibility.md` for
 * which are actually verified). A thin wrapper: all the cryptographic work
 * happens in {@link encryptStream}, this only bridges the two shapes.
 *
 * @example
 * ```ts
 * import { createReadStream, createWriteStream } from 'node:fs';
 * import { Readable, Writable } from 'node:stream';
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate();
 * await Readable.toWeb(createReadStream('large-file.bin'))
 *   .pipeThrough(pqc.encryptWebStream(pair.publicKey))
 *   .pipeTo(Writable.toWeb(createWriteStream('large-file.bin.enc')));
 * ```
 */
export function encryptWebStream(
  publicKey: PublicKey<KemAlgorithm>,
  options?: StreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  return toTransformStream((input) => encryptStream(publicKey, input, options));
}

/**
 * {@link decryptStream} as a Web Streams `TransformStream`. Same
 * incremental-release property as {@link decryptStream} applies here too —
 * see its documentation. Piping into a `TransformStream` does not change
 * that property: bytes written to a downstream sink before the pipe
 * completes are provisional, and the sink must be treated as incomplete
 * until `pipeTo`'s returned promise resolves without rejecting.
 *
 * @example
 * ```ts
 * import { createReadStream, createWriteStream } from 'node:fs';
 * import { Readable, Writable } from 'node:stream';
 * import { pqc } from '@pqc-sdk/core';
 *
 * // pipeTo's promise rejecting means the sink file holds an incomplete,
 * // unverified prefix — callers must delete/ignore it on rejection, never
 * // treat a partially-written output file as done.
 * await Readable.toWeb(createReadStream('large-file.bin.enc'))
 *   .pipeThrough(pqc.decryptWebStream(pair.secretKey))
 *   .pipeTo(Writable.toWeb(createWriteStream('large-file.bin')));
 * ```
 */
export function decryptWebStream(
  secretKey: SecretKey<KemAlgorithm>,
): TransformStream<Uint8Array, Uint8Array> {
  return toTransformStream((input) => decryptStream(secretKey, input));
}
