import { describe, expect, it } from 'vitest';

import type { KemAlgorithm } from './types.js';
import { PqcError } from './errors.js';
import { generate } from './keys.js';
import { decryptStream, encryptStream } from './stream.js';

/**
 * Core primitive functionality, both KEMs (docs/proposals/streaming-encryption.md
 * Day 1 + Day 2). The full mutation-check suite (truncation, reorder,
 * duplicate, cross-stream swap, final-flag games, trailing garbage) lives in
 * stream-mutations.test.ts — this file covers the primitive works at all,
 * plus the nonce arithmetic cross-check against age's published STREAM
 * algorithm.
 */

const utf8 = new TextEncoder();
const utf8Decode = new TextDecoder();

const KEM_CIPHERTEXT_LENGTH: Record<KemAlgorithm, number> = {
  'ml-kem-768': 1088,
  'x-wing': 1120,
};
const ALGORITHMS: readonly KemAlgorithm[] = ['ml-kem-768', 'x-wing'];

// async is required to satisfy the AsyncIterable<Uint8Array> shape
// encryptStream/decryptStream take; nothing here genuinely needs to await.
// eslint-disable-next-line @typescript-eslint/require-await
export async function* single(data: Uint8Array): AsyncGenerator<Uint8Array> {
  yield data;
}

export async function collect(chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of chunks) {
    parts.push(chunk);
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// eslint-disable-next-line @typescript-eslint/require-await -- see `single` above.
export async function* asChunks(
  data: Uint8Array,
  sourceChunkSize: number,
): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < data.length; i += sourceChunkSize) {
    yield data.subarray(i, i + sourceChunkSize);
  }
}

describe.each(ALGORITHMS)('encryptStream/decryptStream: roundtrips (%s)', (algorithm) => {
  const kemCtLength = KEM_CIPHERTEXT_LENGTH[algorithm];

  it('round-trips a single-chunk payload with the default chunk size', async () => {
    const pair = await generate({ algorithm });
    const plaintext = utf8.encode('streamed data, fits in one chunk');
    const ciphertext = await collect(encryptStream(pair.publicKey, single(plaintext)));
    const decrypted = await collect(decryptStream(pair.secretKey, single(ciphertext)));
    expect(utf8Decode.decode(decrypted)).toBe('streamed data, fits in one chunk');
  });

  it('round-trips an empty payload as a single empty final chunk', async () => {
    const pair = await generate({ algorithm });
    const ciphertext = await collect(encryptStream(pair.publicKey, single(new Uint8Array(0))));
    // header (3 bytes + KEM ciphertext) + 16-byte tag-only final chunk.
    expect(ciphertext.length).toBe(3 + kemCtLength + 16);
    const decrypted = await collect(decryptStream(pair.secretKey, single(ciphertext)));
    expect(decrypted.length).toBe(0);
  });

  it('round-trips a payload spanning many chunks with a small chunkSize', async () => {
    const pair = await generate({ algorithm });
    const chunkSize = 8;
    const plaintext = utf8.encode(
      'this plaintext is deliberately longer than eight bytes per chunk',
    );
    const ciphertext = await collect(
      encryptStream(pair.publicKey, single(plaintext), { chunkSize }),
    );
    const decrypted = await collect(decryptStream(pair.secretKey, single(ciphertext)));
    expect(utf8Decode.decode(decrypted)).toBe(utf8Decode.decode(plaintext));
  });

  it('round-trips a payload exactly divisible by chunkSize (full-size final chunk)', async () => {
    const pair = await generate({ algorithm });
    const chunkSize = 8;
    const plaintext = utf8.encode('16-bytes'.repeat(2)); // exactly 16 bytes = 2 * chunkSize
    expect(plaintext.length).toBe(16);
    const ciphertext = await collect(
      encryptStream(pair.publicKey, single(plaintext), { chunkSize }),
    );
    // 2 full chunks, no trailing empty chunk: 2 * (chunkSize + 16 tag).
    expect(ciphertext.length).toBe(3 + kemCtLength + 2 * (chunkSize + 16));
    const decrypted = await collect(decryptStream(pair.secretKey, single(ciphertext)));
    expect(utf8Decode.decode(decrypted)).toBe(utf8Decode.decode(plaintext));
  });

  it('is insensitive to the input iterable granularity (byte-at-a-time source)', async () => {
    const pair = await generate({ algorithm });
    const chunkSize = 8;
    const plaintext = utf8.encode('granularity should not matter at all here');
    const ciphertext = await collect(
      encryptStream(pair.publicKey, asChunks(plaintext, 1), { chunkSize }),
    );
    // Feed the ciphertext back in awkward, non-chunk-aligned pieces too.
    const decrypted = await collect(decryptStream(pair.secretKey, asChunks(ciphertext, 3)));
    expect(utf8Decode.decode(decrypted)).toBe(utf8Decode.decode(plaintext));
  });

  it('encryptStream default chunk size matches the documented 64 KiB', async () => {
    const pair = await generate({ algorithm });
    const plaintext = new Uint8Array(65536 + 10); // just over one default chunk
    const ciphertext = await collect(encryptStream(pair.publicKey, single(plaintext)));
    // header + one full 64 KiB chunk (65536+16) + a 10-byte final chunk (10+16).
    expect(ciphertext.length).toBe(3 + kemCtLength + (65536 + 16) + (10 + 16));
  });

  it('produces the documented version byte and header id', async () => {
    const pair = await generate({ algorithm });
    const ciphertext = await collect(encryptStream(pair.publicKey, single(new Uint8Array(1))));
    const expectedVersion = algorithm === 'ml-kem-768' ? 0x03 : 0x04;
    const expectedHeaderId = algorithm === 'ml-kem-768' ? 0x01 : 0x02;
    expect(ciphertext[0]).toBe(expectedVersion);
    expect(ciphertext[1]).toBe(expectedHeaderId);
  });
});

describe.each(ALGORITHMS)('encryptStream: chunkSize validation (%s)', (algorithm) => {
  it('rejects a non-power-of-two chunkSize', async () => {
    const pair = await generate({ algorithm });
    await expect(
      collect(encryptStream(pair.publicKey, single(new Uint8Array(1)), { chunkSize: 100 })),
    ).rejects.toMatchObject({ code: 'INVALID_CHUNK_SIZE' });
  });

  it('accepts the smallest valid chunkSize (2^0 = 1 byte)', async () => {
    const pair = await generate({ algorithm });
    const ciphertext = await collect(
      encryptStream(pair.publicKey, single(utf8.encode('hi')), { chunkSize: 1 }),
    );
    const decrypted = await collect(decryptStream(pair.secretKey, single(ciphertext)));
    expect(utf8Decode.decode(decrypted)).toBe('hi');
  });

  it('rejects a zero chunkSize', async () => {
    const pair = await generate({ algorithm });
    await expect(
      collect(encryptStream(pair.publicKey, single(new Uint8Array(1)), { chunkSize: 0 })),
    ).rejects.toBeInstanceOf(PqcError);
  });

  it('rejects a chunkSize above the maximum (2^24)', async () => {
    const pair = await generate({ algorithm });
    await expect(
      collect(encryptStream(pair.publicKey, single(new Uint8Array(1)), { chunkSize: 2 ** 25 })),
    ).rejects.toBeInstanceOf(PqcError);
  });
});

/**
 * Cross-check against age's published STREAM algorithm
 * (github.com/C2SP/C2SP/blob/main/age.md "Payload"; reference implementation
 * github.com/str4d/rage age/src/primitives/stream.rs): nonce = 11-byte
 * big-endian counter, then a 1-byte flag (0x00/0x01). rage computes this as
 * `(counter << 8) | flag`, serialized as the low 12 bytes of a 16-byte
 * big-endian integer — algebraically identical to "BE88(counter) ‖ flag".
 * These expected byte arrays were hand-derived from that published
 * algorithm, independent of this package's own implementation, per
 * docs/proposals/streaming-encryption.md Day 1. ml-kem-768 only: the nonce
 * construction is algorithm-independent (it only depends on the KEM's
 * shared secret being used as the AES key, not on which KEM produced it),
 * so this is not repeated per-KEM.
 */
describe('chunk nonce arithmetic: cross-check against age (via ciphertext structure)', () => {
  it('a single-chunk stream (index 0, final) uses an all-zero-counter, flag=1 nonce', async () => {
    // Indirect check: encrypt/decrypt at chunkSize >= plaintext length forces
    // exactly one chunk at index 0, final=true, nonce = 11 zero bytes ‖ 0x01.
    // We can't read the nonce directly (it's never serialized, by design —
    // serialization-format.md §9.2), but we can verify by encrypting the
    // same plaintext with AES-256-GCM directly using the documented nonce
    // and confirming ciphertext bytes match, proving the implementation
    // used exactly that nonce.
    const { gcm } = await import('@noble/ciphers/aes.js');
    const pair = await generate();
    const plaintext = utf8.encode('short');
    const ciphertext = await collect(encryptStream(pair.publicKey, single(plaintext)));

    // Recover the shared secret the only legitimate way: decapsulate with
    // the secret key, mirroring decryptStream's own logic, to independently
    // recompute what the sealed chunk *should* be under the documented nonce.
    const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
    const header = ciphertext.subarray(0, 3);
    const kemCiphertext = ciphertext.subarray(3, 3 + 1088);
    const sealed = ciphertext.subarray(3 + 1088);
    const sharedSecret = ml_kem768.decapsulate(kemCiphertext, pair.secretKey.bytes);

    const expectedNonce = new Uint8Array(12); // all zero counter
    expectedNonce[11] = 1; // final flag
    const expectedSealed = gcm(sharedSecret, expectedNonce, header).encrypt(plaintext);

    expect(sealed).toEqual(expectedSealed);
  });

  it('chunk index 1 (BE88(1) = 10 zero bytes then 0x01) matches a hand-built nonce', async () => {
    const { gcm } = await import('@noble/ciphers/aes.js');
    const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
    const pair = await generate();
    const chunkSize = 4;
    // Exactly 2 chunks: index 0 (non-final, full 4 bytes) and index 1 (final).
    const plaintext = utf8.encode('abcdEF'); // 6 bytes: chunk0="abcd", chunk1="EF"
    const ciphertext = await collect(
      encryptStream(pair.publicKey, single(plaintext), { chunkSize }),
    );

    const header = ciphertext.subarray(0, 3);
    const kemCiphertext = ciphertext.subarray(3, 3 + 1088);
    const sharedSecret = ml_kem768.decapsulate(kemCiphertext, pair.secretKey.bytes);

    const chunk0Sealed = ciphertext.subarray(3 + 1088, 3 + 1088 + chunkSize + 16);
    const chunk1Sealed = ciphertext.subarray(3 + 1088 + chunkSize + 16);

    const nonce0 = new Uint8Array(12); // index 0, flag 0x00 (all zero)
    const expectedChunk0 = gcm(sharedSecret, nonce0, header).encrypt(utf8.encode('abcd'));
    expect(chunk0Sealed).toEqual(expectedChunk0);

    const nonce1 = new Uint8Array(12);
    nonce1[10] = 1; // BE88(1): 10 zero bytes then 0x01 in the counter's low byte
    nonce1[11] = 1; // final flag
    const expectedChunk1 = gcm(sharedSecret, nonce1, header).encrypt(utf8.encode('EF'));
    expect(chunk1Sealed).toEqual(expectedChunk1);
  });
});
