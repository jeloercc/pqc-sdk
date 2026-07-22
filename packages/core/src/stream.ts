import { gcm } from '@noble/ciphers/aes.js';

import { requireKey } from './algorithms.js';
import { PqcError } from './errors.js';
import type { KemAlgorithm, PublicKey, SecretKey } from './types.js';

const GCM_TAG_LENGTH = 16;
const NONCE_LENGTH = 12;
const COUNTER_BYTES = 11;
const MAX_CHUNK_INDEX = (1n << BigInt(COUNTER_BYTES * 8)) - 1n;

// No floor beyond 2^0 (1 byte): unlike the ceiling, a minimum chunk size
// isn't a cryptographic requirement (the nonce scheme is sound at any
// positive chunk size) — it would only be a usability guardrail, and one
// that would conflict with wanting small chunkSize values for compact
// golden-vector fixtures. The default (2^16) is what "safe defaults
// always" actually protects.
const MIN_CHUNK_SIZE_EXPONENT = 0; // 1 byte
const MAX_CHUNK_SIZE_EXPONENT = 24; // 16 MiB
const DEFAULT_CHUNK_SIZE_EXPONENT = 16; // 64 KiB, matches age's STREAM default

/**
 * Streaming envelope version byte per KEM (docs/serialization-format.md
 * §9.1) — independent of the one-shot version bytes in algorithms.ts.
 */
const STREAM_ENVELOPE_VERSION: Record<KemAlgorithm, number> = {
  'ml-kem-768': 3,
  'x-wing': 4,
};

/** Options for {@link encryptStream}. */
export interface StreamOptions {
  /**
   * Plaintext bytes per chunk. Must be a power of two between 2^10 (1 KiB)
   * and 2^24 (16 MiB). Default: 2^16 (64 KiB, matching age's STREAM
   * default) — most callers should not set this.
   */
  chunkSize?: number;
}

function chunkSizeExponent(chunkSize: number | undefined): number {
  if (chunkSize === undefined) {
    return DEFAULT_CHUNK_SIZE_EXPONENT;
  }
  const exponent = Math.log2(chunkSize);
  if (
    !Number.isInteger(exponent) ||
    exponent < MIN_CHUNK_SIZE_EXPONENT ||
    exponent > MAX_CHUNK_SIZE_EXPONENT
  ) {
    throw new PqcError(
      'INVALID_CHUNK_SIZE',
      `chunkSize must be a power of two between 2^${MIN_CHUNK_SIZE_EXPONENT} and 2^${MAX_CHUNK_SIZE_EXPONENT}, got ${String(chunkSize)}`,
    );
  }
  return exponent;
}

/**
 * age's STREAM nonce (github.com/C2SP/C2SP/blob/main/age.md, "Payload"),
 * adopted verbatim (docs/serialization-format.md §9.3): an 11-byte
 * big-endian chunk counter, starting at 0, followed by a 1-byte flag —
 * `0x00` for every chunk except the last, which gets `0x01`.
 */
function chunkNonce(index: bigint, final: boolean): Uint8Array {
  if (index > MAX_CHUNK_INDEX) {
    // Unreachable by any realistic input (2^88 chunks); a defensive bound,
    // not a limit ever expected to trigger — see serialization-format.md §9.5.
    throw new PqcError('STREAM_OVERFLOW', 'Stream exceeded the maximum chunk count');
  }
  const nonce = new Uint8Array(NONCE_LENGTH);
  let value = index;
  for (let i = COUNTER_BYTES - 1; i >= 0; i--) {
    nonce[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  nonce[COUNTER_BYTES] = final ? 1 : 0;
  return nonce;
}

interface PlaintextChunk {
  readonly data: Uint8Array;
  readonly final: boolean;
}

/**
 * Re-chunks an arbitrary-granularity byte iterable into fixed-size pieces,
 * determining finality by lookahead: a chunk is only ever reported final
 * once the source is confirmed exhausted. Safe for the *encode* side only
 * (encryptStream) — the encoder has ground truth about when its own input
 * ends. Decryption cannot use this: an adversary controls what "ends" a
 * ciphertext stream, so decryptStream instead resolves finality by trial
 * decryption (see decryptStream below and serialization-format.md §9.3).
 */
async function* rechunk(
  source: AsyncIterable<Uint8Array>,
  segmentSize: number,
): AsyncGenerator<PlaintextChunk> {
  const pending: Uint8Array[] = [];
  let pendingLength = 0;
  const iterator = source[Symbol.asyncIterator]();
  let sourceDone = false;

  function takeExact(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let offset = 0;
    while (offset < n) {
      const head = pending[0]!;
      const need = n - offset;
      if (head.length <= need) {
        out.set(head, offset);
        offset += head.length;
        pending.shift();
      } else {
        out.set(head.subarray(0, need), offset);
        pending[0] = head.subarray(need);
        offset += need;
      }
    }
    pendingLength -= n;
    return out;
  }

  async function fill(): Promise<void> {
    while (pendingLength <= segmentSize && !sourceDone) {
      // iterator.next() types its return via TReturn (defaulted to `any` on
      // Symbol.asyncIterator's signature); asserted away here since only
      // `value`/`done` are ever read, never the generator's return value.
      const { value, done } = (await iterator.next()) as IteratorResult<Uint8Array, void>;
      if (done) {
        sourceDone = true;
        break;
      }
      if (value.length === 0) {
        continue;
      }
      pending.push(value);
      pendingLength += value.length;
    }
  }

  await fill();

  if (pendingLength === 0 && sourceDone) {
    yield { data: new Uint8Array(0), final: true };
    return;
  }

  for (;;) {
    if (pendingLength > segmentSize) {
      yield { data: takeExact(segmentSize), final: false };
      await fill();
      continue;
    }
    yield { data: takeExact(pendingLength), final: true };
    return;
  }
}

/**
 * Hybrid streaming encryption: like {@link encrypt}, but for payloads too
 * large to hold in memory at once. Encapsulates one KEM secret per stream
 * (fresh, single-use, same as {@link encrypt}) and seals fixed-size chunks
 * of `plaintext` under it, using age's STREAM chunk framing
 * (docs/serialization-format.md §9). Bounded memory: roughly one chunk at a
 * time, independent of total payload size.
 *
 * Yields the 3-byte header and KEM ciphertext first, then one sealed chunk
 * per plaintext chunk. Concatenating everything yielded reproduces the full
 * wire format §9 describes.
 *
 * Not yet part of the public `pqc` surface (`docs/proposals/streaming-encryption.md`
 * Day 3 exports it) — this example imports the module directly, as the
 * internal test suite does until then.
 *
 * @example
 * ```ts
 * import { generate } from './keys.js';
 * import { encryptStream } from './stream.js';
 *
 * const pair = await generate();
 * async function* source() {
 *   yield new TextEncoder().encode('streamed data');
 * }
 * const parts: Uint8Array[] = [];
 * for await (const chunk of encryptStream(pair.publicKey, source())) {
 *   parts.push(chunk);
 * }
 * ```
 */
export async function* encryptStream(
  publicKey: PublicKey<KemAlgorithm>,
  plaintext: AsyncIterable<Uint8Array>,
  options?: StreamOptions,
): AsyncGenerator<Uint8Array> {
  const spec = requireKey(publicKey, 'kem', 'public', 'encryptStream');
  const exponent = chunkSizeExponent(options?.chunkSize);
  const chunkSize = 2 ** exponent;
  const version = STREAM_ENVELOPE_VERSION[publicKey.algorithm];

  const { cipherText: kemCiphertext, sharedSecret } = spec.kem.encapsulate(publicKey.bytes);
  const header = new Uint8Array([version, spec.headerId, exponent]);

  const prefix = new Uint8Array(header.length + kemCiphertext.length);
  prefix.set(header, 0);
  prefix.set(kemCiphertext, header.length);
  yield prefix;

  let index = 0n;
  for await (const { data, final } of rechunk(plaintext, chunkSize)) {
    const nonce = chunkNonce(index, final);
    yield gcm(sharedSecret, nonce, header).encrypt(data);
    index += 1n;
  }
}

/** Removes and returns exactly `n` bytes from the front of `pending`. */
function takeExactFrom(pending: { chunks: Uint8Array[]; length: number }, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let offset = 0;
  while (offset < n) {
    const head = pending.chunks[0]!;
    const need = n - offset;
    if (head.length <= need) {
      out.set(head, offset);
      offset += head.length;
      pending.chunks.shift();
    } else {
      out.set(head.subarray(0, need), offset);
      pending.chunks[0] = head.subarray(need);
      offset += need;
    }
  }
  pending.length -= n;
  return out;
}

/** Reads up to `n` bytes; returns fewer only once the source is exhausted. */
async function readUpTo(
  iterator: AsyncIterator<Uint8Array>,
  pending: { chunks: Uint8Array[]; length: number },
  n: number,
): Promise<Uint8Array> {
  while (pending.length < n) {
    // See the matching comment in rechunk()'s fill() above.
    const { value, done } = (await iterator.next()) as IteratorResult<Uint8Array, void>;
    if (done) {
      break;
    }
    if (value.length === 0) {
      continue;
    }
    pending.chunks.push(value);
    pending.length += value.length;
  }
  return takeExactFrom(pending, Math.min(n, pending.length));
}

function decryptionFailed(): PqcError {
  return new PqcError(
    'DECRYPTION_FAILED',
    'Decryption failed: tampered ciphertext or wrong secret key',
  );
}

/**
 * Decrypts a stream produced by {@link encryptStream}, discriminating the
 * envelope on its leading version byte the same way {@link decrypt} does
 * (`0x03` = ml-kem-768 streaming, `0x04` = x-wing streaming; unrelated to
 * and rejected the same way as the one-shot `0x01`/`0x02` bytes). Yields
 * plaintext chunk by chunk as each chunk authenticates — see the
 * incremental-release property in docs/serialization-format.md §9.3: a
 * truncated or tampered stream can yield genuine prefix chunks before the
 * iterable throws `PqcError` with code `DECRYPTION_FAILED`. Only the
 * iterable completing without throwing means the full plaintext is
 * authentic — do not treat any individual yielded chunk as proof the
 * stream is complete.
 *
 * Not yet part of the public `pqc` surface (`docs/proposals/streaming-encryption.md`
 * Day 3 exports it) — this example imports the module directly, as the
 * internal test suite does until then.
 *
 * @example
 * ```ts
 * import { generate } from './keys.js';
 * import { encryptStream, decryptStream } from './stream.js';
 *
 * const pair = await generate();
 * async function* source() {
 *   yield new TextEncoder().encode('streamed data');
 * }
 * const ciphertextChunks: Uint8Array[] = [];
 * for await (const chunk of encryptStream(pair.publicKey, source())) {
 *   ciphertextChunks.push(chunk);
 * }
 * async function* replay() {
 *   yield* ciphertextChunks;
 * }
 * const parts: Uint8Array[] = [];
 * for await (const chunk of decryptStream(pair.secretKey, replay())) {
 *   parts.push(chunk); // provisional until the loop finishes without throwing
 * }
 * ```
 */
export async function* decryptStream(
  secretKey: SecretKey<KemAlgorithm>,
  ciphertext: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const spec = requireKey(secretKey, 'kem', 'secret', 'decryptStream');
  const iterator = ciphertext[Symbol.asyncIterator]();
  const pending = { chunks: [] as Uint8Array[], length: 0 };

  const headerLength = 3 + spec.ciphertextLength;
  const headerBytes = await readUpTo(iterator, pending, headerLength);
  if (headerBytes.length < headerLength) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Ciphertext is truncated or was not produced by pqc.encryptStream',
    );
  }

  const expectedVersion = STREAM_ENVELOPE_VERSION[secretKey.algorithm];
  const version = headerBytes[0];
  const headerId = headerBytes[1];
  const exponent = headerBytes[2]!;

  if (version !== expectedVersion || headerId !== spec.headerId) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Unknown header: the ciphertext does not match this version or algorithm',
    );
  }
  if (exponent < MIN_CHUNK_SIZE_EXPONENT || exponent > MAX_CHUNK_SIZE_EXPONENT) {
    throw new PqcError('INVALID_CIPHERTEXT', 'Ciphertext declares an out-of-range chunk size');
  }

  const header = headerBytes.subarray(0, 3);
  const kemCiphertext = headerBytes.subarray(3);
  const segmentSize = 2 ** exponent + GCM_TAG_LENGTH;

  let sharedSecret: Uint8Array;
  try {
    sharedSecret = spec.kem.decapsulate(kemCiphertext, secretKey.bytes);
  } catch {
    throw decryptionFailed();
  }

  let index = 0n;
  for (;;) {
    const sealed = await readUpTo(iterator, pending, segmentSize);

    if (sealed.length < segmentSize) {
      // Unambiguous: the source is exhausted, so this can only be the
      // final chunk (serialization-format.md §9.3 step 1).
      try {
        yield gcm(sharedSecret, chunkNonce(index, true), header).decrypt(sealed);
      } catch {
        throw decryptionFailed();
      }
      return;
    }

    // Exactly segmentSize bytes: ambiguous between "more chunks follow" and
    // "this happens to be a full-size final chunk" (§9.3 step 2). Resolve
    // by trial decryption, non-final first (the common case).
    try {
      const plaintext = gcm(sharedSecret, chunkNonce(index, false), header).decrypt(sealed);
      yield plaintext;
      index += 1n;
      continue;
    } catch {
      // Fall through: maybe this is genuinely a full-size final chunk.
    }

    let plaintext: Uint8Array;
    try {
      plaintext = gcm(sharedSecret, chunkNonce(index, true), header).decrypt(sealed);
    } catch {
      throw decryptionFailed();
    }
    yield plaintext;

    // Reject trailing data appended after a legitimate stream end.
    const trailing = await readUpTo(iterator, pending, 1);
    if (trailing.length > 0) {
      throw decryptionFailed();
    }
    return;
  }
}
