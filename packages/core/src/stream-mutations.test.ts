import { describe, expect, it } from 'vitest';

import type { KemAlgorithm, SecretKey } from './types.js';
import { PqcError } from './errors.js';
import { generate } from './keys.js';
import { decryptStream, encryptStream } from './stream.js';
import { asChunks, collect, single } from './stream.test.js';

/**
 * Day 2 of the streaming-encryption sprint
 * (docs/proposals/streaming-encryption.md §4): the full mutation-check
 * suite, run against both KEMs. Every case here tampers one region of a
 * genuine ciphertext and asserts fail-closed behavior with the documented
 * `PqcError` code — the crypto-review mutation-check rule
 * (.claude/rules/crypto-review.md), applied to chunk boundaries.
 *
 * Central to this suite: the incremental-release property
 * (serialization-format.md §9.3) means a truncated/tampered stream can
 * legitimately yield genuine prefix chunks before throwing. Tests assert
 * the *exact* prefix, not just "it eventually throws" — a suite that only
 * checked "rejects.toThrow()" could pass even if the implementation leaked
 * one extra unauthenticated chunk, which is exactly the bug class this
 * exists to catch.
 */

const utf8 = new TextEncoder();

const KEM_CIPHERTEXT_LENGTH: Record<KemAlgorithm, number> = {
  'ml-kem-768': 1088,
  'x-wing': 1120,
};
const ALGORITHMS: readonly KemAlgorithm[] = ['ml-kem-768', 'x-wing'];

interface Stream {
  ciphertext: Uint8Array;
  secretKey: SecretKey<KemAlgorithm>;
  headerLength: number;
  chunkSize: number;
  segmentSize: number; // chunkSize + 16 (GCM tag)
}

async function buildStream(
  algorithm: KemAlgorithm,
  plaintext: Uint8Array,
  chunkSize: number,
): Promise<Stream> {
  const pair = await generate({ algorithm });
  const ciphertext = await collect(encryptStream(pair.publicKey, single(plaintext), { chunkSize }));
  return {
    ciphertext,
    secretKey: pair.secretKey,
    headerLength: 3 + KEM_CIPHERTEXT_LENGTH[algorithm],
    chunkSize,
    segmentSize: chunkSize + 16,
  };
}

/** Runs decryptStream to completion or failure, returning whichever chunks
 * were yielded before any error, plus the error if one was thrown. */
async function drain(
  secretKey: Stream['secretKey'],
  ciphertext: Uint8Array,
): Promise<{ chunks: Uint8Array[]; error: unknown }> {
  const chunks: Uint8Array[] = [];
  try {
    for await (const chunk of decryptStream(secretKey, single(ciphertext))) {
      chunks.push(chunk);
    }
    return { chunks, error: undefined };
  } catch (error) {
    return { chunks, error };
  }
}

describe.each(ALGORITHMS)('streaming mutation suite (%s)', (algorithm) => {
  const chunkSize = 8;

  describe('truncation', () => {
    it('mid-chunk truncation fails closed with no genuine chunks lost', async () => {
      // 3 chunks: "abcdefgh" / "ijklmnop" / "qr" (18 bytes, chunkSize 8).
      const plaintext = utf8.encode('abcdefghijklmnopqr');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      // Cut inside chunk 1's sealed bytes (not on a segment boundary).
      const cutAt = s.headerLength + s.segmentSize + 3;
      const truncated = s.ciphertext.subarray(0, cutAt);

      const { chunks, error } = await drain(s.secretKey, truncated);
      // Chunk 0 fully present and genuine: it authenticates before the cut
      // is ever reached.
      expect(chunks).toHaveLength(1);
      expect(utf8.encode('abcdefgh')).toEqual(chunks[0]);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });

    it('chunk-aligned truncation (the dangerous case) yields the prefix THEN throws', async () => {
      // 3 chunks: "abcdefgh" / "ijklmnop" / "qr" (18 bytes, chunkSize 8).
      const plaintext = utf8.encode('abcdefghijklmnopqr');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      // Drop the entire final chunk, ending exactly on a segment boundary.
      const cutAt = s.headerLength + 2 * s.segmentSize;
      expect(cutAt).toBeLessThan(s.ciphertext.length); // sanity: something was cut
      const truncated = s.ciphertext.subarray(0, cutAt);

      const { chunks, error } = await drain(s.secretKey, truncated);
      // The incremental-release property: chunk 0 authenticates fine.
      // Chunk 1 ("ijklmnop") was genuinely sealed non-final (flag=0) — the
      // decoder tries flag=0 first, it matches, so chunk 1 legitimately
      // authenticates too and is released as real output. Only once the
      // decoder looks for chunk 2 and finds nothing does it discover the
      // stream never produced a final=1 chunk.
      expect(chunks).toHaveLength(2);
      expect(utf8.encode('abcdefgh')).toEqual(chunks[0]);
      expect(utf8.encode('ijklmnop')).toEqual(chunks[1]);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });

    it('never silently completes: draining a truncated stream always ends in an error, not a clean return', async () => {
      const plaintext = utf8.encode('abcdefghijklmnopqr');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      for (let cutAt = s.headerLength; cutAt < s.ciphertext.length; cutAt += 3) {
        const { error } = await drain(s.secretKey, s.ciphertext.subarray(0, cutAt));
        expect(error, `truncating at byte ${String(cutAt)} must fail closed`).toBeInstanceOf(
          PqcError,
        );
      }
    });
  });

  describe('reorder', () => {
    it('swapping two chunks fails closed at the first displaced chunk', async () => {
      // 3 chunks: "AAAAAAAA" / "BBBBBBBB" / "CC".
      const plaintext = utf8.encode('AAAAAAAABBBBBBBBCC');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      const chunk0 = s.ciphertext.subarray(s.headerLength, s.headerLength + s.segmentSize);
      const chunk1 = s.ciphertext.subarray(
        s.headerLength + s.segmentSize,
        s.headerLength + 2 * s.segmentSize,
      );
      const rest = s.ciphertext.subarray(s.headerLength + 2 * s.segmentSize);

      const reordered = new Uint8Array(s.ciphertext.length);
      reordered.set(s.ciphertext.subarray(0, s.headerLength), 0);
      reordered.set(chunk1, s.headerLength); // chunk 1 first
      reordered.set(chunk0, s.headerLength + s.segmentSize); // chunk 0 second
      reordered.set(rest, s.headerLength + 2 * s.segmentSize);

      const { chunks, error } = await drain(s.secretKey, reordered);
      // Position 0 now holds chunk 1's bytes, sealed under index 1 — the
      // decoder computes nonce for index 0 and neither flag matches.
      expect(chunks).toHaveLength(0);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  });

  describe('duplicate/insert', () => {
    it('duplicating a non-final chunk fails closed after the genuine prefix', async () => {
      // 3 chunks: "AAAAAAAA" / "BBBBBBBB" / "CC".
      const plaintext = utf8.encode('AAAAAAAABBBBBBBBCC');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      const chunk0 = s.ciphertext.subarray(s.headerLength, s.headerLength + s.segmentSize);
      const chunk1 = s.ciphertext.subarray(
        s.headerLength + s.segmentSize,
        s.headerLength + 2 * s.segmentSize,
      );
      const rest = s.ciphertext.subarray(s.headerLength + 2 * s.segmentSize);

      // Insert an extra copy of chunk 1 right after itself: 0, 1, 1, 2.
      const tampered = new Uint8Array(s.ciphertext.length + s.segmentSize);
      tampered.set(s.ciphertext.subarray(0, s.headerLength), 0);
      tampered.set(chunk0, s.headerLength);
      tampered.set(chunk1, s.headerLength + s.segmentSize);
      tampered.set(chunk1, s.headerLength + 2 * s.segmentSize); // duplicate
      tampered.set(rest, s.headerLength + 3 * s.segmentSize);

      const { chunks, error } = await drain(s.secretKey, tampered);
      // Chunk 0 and the first copy of chunk 1 both authenticate genuinely
      // (real bytes, correct expected index). The second copy of chunk 1
      // is read as index 2, but was sealed under index 1 — fails closed.
      expect(chunks).toHaveLength(2);
      expect(utf8.encode('AAAAAAAA')).toEqual(chunks[0]);
      expect(utf8.encode('BBBBBBBB')).toEqual(chunks[1]);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  });

  describe('swap across streams', () => {
    it('splicing a chunk from a different stream fails closed, regardless of position/nonce correctness', async () => {
      const plaintextA = utf8.encode('AAAAAAAABBBBBBBBCC');
      const plaintextB = utf8.encode('XXXXXXXXYYYYYYYYZZ');
      const a = await buildStream(algorithm, plaintextA, chunkSize);
      const pairB = await generate({ algorithm });
      const ciphertextB = await collect(
        encryptStream(pairB.publicKey, single(plaintextB), { chunkSize }),
      );

      // Take B's chunk 1 (same index, same length) and splice it into A's
      // ciphertext at chunk 1's position — same index, same key holder
      // attempting to decrypt, wrong stream entirely.
      const bChunk1 = ciphertextB.subarray(
        a.headerLength + a.segmentSize,
        a.headerLength + 2 * a.segmentSize,
      );
      const spliced = new Uint8Array(a.ciphertext);
      spliced.set(bChunk1, a.headerLength + a.segmentSize);

      const { chunks, error } = await drain(a.secretKey, spliced);
      // Chunk 0 (genuine, untouched) authenticates. The spliced-in chunk 1
      // was sealed under a completely different KEM shared secret — no
      // flag/index guess can recover it.
      expect(chunks).toHaveLength(1);
      expect(utf8.encode('AAAAAAAA')).toEqual(chunks[0]);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  });

  describe('final-flag games', () => {
    it('trailing garbage after a full-size final chunk is rejected (extension attack)', async () => {
      // Exactly 16 bytes at chunkSize=8: final chunk is a genuine full-size
      // chunk (flag=1), the ambiguous case serialization-format.md §9.3
      // resolves by trying flag=0 first, then flag=1.
      const plaintext = utf8.encode('AAAAAAAABBBBBBBB');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      const withTrailingGarbage = new Uint8Array(s.ciphertext.length + 5);
      withTrailingGarbage.set(s.ciphertext, 0);
      withTrailingGarbage.set([1, 2, 3, 4, 5], s.ciphertext.length);

      const { chunks, error } = await drain(s.secretKey, withTrailingGarbage);
      // Both genuine chunks authenticate (they're untouched); the appended
      // bytes are only discovered — and rejected — after the true final
      // chunk is confirmed, via the explicit post-final read.
      expect(chunks).toHaveLength(2);
      expect(utf8.encode('AAAAAAAA')).toEqual(chunks[0]);
      expect(utf8.encode('BBBBBBBB')).toEqual(chunks[1]);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });

    it('trailing garbage after a short final chunk is rejected', async () => {
      // 18 bytes at chunkSize=8: final chunk ("qr") is genuinely short.
      const plaintext = utf8.encode('abcdefghijklmnopqr');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      // Append enough garbage to reach a full segment at the final chunk's
      // position, corrupting what the decoder reads there.
      const garbage = new Uint8Array(s.segmentSize);
      garbage.fill(0xaa);
      const withTrailingGarbage = new Uint8Array(s.ciphertext.length + garbage.length);
      withTrailingGarbage.set(s.ciphertext, 0);
      withTrailingGarbage.set(garbage, s.ciphertext.length);

      const { chunks, error } = await drain(s.secretKey, withTrailingGarbage);
      expect(chunks).toHaveLength(2); // the two genuine non-final chunks
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  });

  describe('edge cases', () => {
    it('single-byte plaintext round-trips (shorter than the GCM tag alone)', async () => {
      const s = await buildStream(algorithm, utf8.encode('x'), chunkSize);
      const decrypted = await collect(decryptStream(s.secretKey, single(s.ciphertext)));
      expect(new TextDecoder().decode(decrypted)).toBe('x');
    });

    it('a genuinely empty final segment (0-byte read) is rejected, never treated as valid', async () => {
      // Truncate a stream to end exactly after the header, before any chunk
      // bytes at all — the sharpest form of "0 bytes where a chunk was
      // expected."
      const s = await buildStream(algorithm, utf8.encode('abcdefgh'), chunkSize);
      const headerOnly = s.ciphertext.subarray(0, s.headerLength);
      const { chunks, error } = await drain(s.secretKey, headerOnly);
      expect(chunks).toHaveLength(0);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });

    it('mutation coverage is granularity-independent (tampered stream fed byte-at-a-time)', async () => {
      const plaintext = utf8.encode('abcdefghijklmnopqr');
      const s = await buildStream(algorithm, plaintext, chunkSize);
      const cutAt = s.headerLength + 2 * s.segmentSize;
      const truncated = s.ciphertext.subarray(0, cutAt);

      const chunks: Uint8Array[] = [];
      let error: unknown;
      try {
        for await (const chunk of decryptStream(s.secretKey, asChunks(truncated, 1))) {
          chunks.push(chunk);
        }
      } catch (e) {
        error = e;
      }
      expect(chunks).toHaveLength(2);
      expect(error).toBeInstanceOf(PqcError);
    });
  });

  describe('header tampering', () => {
    it('rejects a flipped version byte before any KEM or chunk work', async () => {
      const s = await buildStream(algorithm, utf8.encode('abcdefgh'), chunkSize);
      const tampered = new Uint8Array(s.ciphertext);
      tampered[0] = 0xff;
      const { chunks, error } = await drain(s.secretKey, tampered);
      expect(chunks).toHaveLength(0);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
    });

    it('rejects a flipped header id (algorithm) byte', async () => {
      const s = await buildStream(algorithm, utf8.encode('abcdefgh'), chunkSize);
      const tampered = new Uint8Array(s.ciphertext);
      tampered[1] = 0xff;
      const { chunks, error } = await drain(s.secretKey, tampered);
      expect(chunks).toHaveLength(0);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
    });

    it('rejects an out-of-range chunk-size exponent declared in the header', async () => {
      const s = await buildStream(algorithm, utf8.encode('abcdefgh'), chunkSize);
      const tampered = new Uint8Array(s.ciphertext);
      tampered[2] = 25; // beyond MAX_CHUNK_SIZE_EXPONENT (24)
      const { chunks, error } = await drain(s.secretKey, tampered);
      expect(chunks).toHaveLength(0);
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
    });
  });
});

describe('cross-KEM key confusion', () => {
  it('an ml-kem-768 stream offered to an x-wing secret key fails closed with INVALID_CIPHERTEXT', async () => {
    const mlKemPair = await generate({ algorithm: 'ml-kem-768' });
    const xwingPair = await generate({ algorithm: 'x-wing' });
    const ciphertext = await collect(
      encryptStream(mlKemPair.publicKey, single(utf8.encode('abcdefgh')), { chunkSize: 8 }),
    );
    const { chunks, error } = await drain(xwingPair.secretKey, ciphertext);
    expect(chunks).toHaveLength(0);
    expect(error).toBeInstanceOf(PqcError);
    expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
  });

  it('an x-wing stream offered to an ml-kem-768 secret key fails closed with INVALID_CIPHERTEXT', async () => {
    const mlKemPair = await generate({ algorithm: 'ml-kem-768' });
    const xwingPair = await generate({ algorithm: 'x-wing' });
    const ciphertext = await collect(
      encryptStream(xwingPair.publicKey, single(utf8.encode('abcdefgh')), { chunkSize: 8 }),
    );
    const { chunks, error } = await drain(mlKemPair.secretKey, ciphertext);
    expect(chunks).toHaveLength(0);
    expect(error).toBeInstanceOf(PqcError);
    expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
  });

  it('a one-shot v1/v2 ciphertext offered to decryptStream fails closed as an unknown version', async () => {
    const { encrypt } = await import('./encrypt.js');
    const pair = await generate({ algorithm: 'ml-kem-768' });
    const oneShot = await encrypt('one-shot payload', pair.publicKey);
    const { chunks, error } = await drain(pair.secretKey, oneShot);
    expect(chunks).toHaveLength(0);
    expect(error).toBeInstanceOf(PqcError);
    expect((error as PqcError).code).toBe('INVALID_CIPHERTEXT');
  });
});
