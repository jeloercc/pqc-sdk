import { afterEach, describe, expect, it, vi } from 'vitest';

import { encapsulateTo, KEM_ALGORITHMS } from '../../../algorithms.js';
import { PqcError } from '../../../errors.js';
import { pqc } from '../../../index.js';

const cases = (['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'] as const).flatMap((algorithm) =>
  (['throw', 'absent', 'short'] as const).map((mode) => ({ algorithm, mode })),
);

describe('Standalone ML-KEM entropy attribution for every parameter set', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(cases)('$algorithm KEM draw: $mode', async ({ algorithm, mode }) => {
    const pair = await pqc.keys.generate({ algorithm });
    const lengths: number[] = [];
    const real = globalThis.crypto;
    vi.stubGlobal(
      'crypto',
      mode === 'absent'
        ? {}
        : {
            subtle: real.subtle,
            getRandomValues: (target: Uint8Array) => {
              lengths.push(target.length);
              if (mode === 'throw') throw new Error('Synthetic private host message');
              return target.subarray(0, 0);
            },
          },
    );
    try {
      try {
        encapsulateTo(KEM_ALGORITHMS[algorithm], pair.publicKey.bytes, algorithm);
        expect.unreachable('KEM randomness should fail');
      } catch (error) {
        expect(error).toBeInstanceOf(PqcError);
        expect((error as PqcError).code).toBe('RBG_FAILURE');
        expect((error as Error).message).not.toContain('Synthetic private host message');
        expect((error as Error).message).not.toMatch(/[0-9a-f]{32,}/i);
      }
      await expect(pqc.encrypt('synthetic input', pair.publicKey)).rejects.toMatchObject({
        code: 'RBG_FAILURE',
      });
      // The first failing draw is ML-KEM's 32-byte message, not GCM's later 12-byte nonce.
      expect(lengths).toEqual(mode === 'absent' ? [] : [32, 32]);
    } finally {
      vi.unstubAllGlobals();
    }
    const ciphertext = await pqc.encrypt('synthetic input', pair.publicKey);
    await expect(pqc.decrypt(ciphertext, pair.secretKey)).resolves.toEqual(
      new TextEncoder().encode('synthetic input'),
    );
  });
});
