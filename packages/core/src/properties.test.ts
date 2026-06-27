import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { fromBase64Url, toBase64Url } from './base64url.js';
import { PqcError } from './errors.js';
import { pqc } from './index.js';
import { generateKeyPairFromSeed } from './keys.js';
import type { Algorithm } from './types.js';

// Property-based companions to the example-based suite: each crypto invariant is
// asserted over many generated inputs instead of a few hand-picked ones.
//
// Determinism: every `fc.assert` runs with a fixed `seed`, so CI is reproducible
// and a failure always replays the same counterexample. Boundedness: ML-DSA
// signing is ~0.4s per call, so crypto-heavy properties use a small `numRuns`
// and reuse a single key pair across generated payloads, while the cheap
// pure-function properties (base64url) run many more.
const SEED = 0x5eed_1234;
const cheap = { seed: SEED, numRuns: 500 } as const;
const kem = { seed: SEED, numRuns: 30 } as const;
const sig = { seed: SEED, numRuns: 12 } as const;

// CI runs the suite under v8 coverage, which makes the post-quantum primitives
// several times slower than an uninstrumented run. Give the crypto-heavy
// properties a generous timeout so coverage mode can never flake them, while
// the small numRuns above keep the actual wall-clock bounded.
const CRYPTO_TIMEOUT = 30_000;

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

describe('property: base64url', () => {
  it('fromBase64Url(toBase64Url(x)) === x for any byte array', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 1024 }), (x) => {
        expect(bytesEqual(fromBase64Url(toBase64Url(x)), x)).toBe(true);
      }),
      cheap,
    );
  });
});

describe('property: key serialization', () => {
  it('deserialize(serialize(k)) equals k for any generated key', () => {
    fc.assert(
      fc.property(
        fc.constantFrom<Algorithm>('ml-kem-768', 'ml-dsa-65'),
        // 64 raw bytes is enough for either seed length (KEM 64, DSA 32).
        fc.uint8Array({ minLength: 64, maxLength: 64 }),
        (algorithm, rawSeed) => {
          const seedLength = algorithm === 'ml-kem-768' ? 64 : 32;
          const pair = generateKeyPairFromSeed(algorithm, rawSeed.subarray(0, seedLength));

          for (const key of [pair.publicKey, pair.secretKey]) {
            const restored = pqc.keys.deserialize(pqc.keys.serialize(key));
            expect(restored.algorithm).toBe(key.algorithm);
            expect(restored.use).toBe(key.use);
            expect(bytesEqual(restored.bytes, key.bytes)).toBe(true);
          }
        },
      ),
      kem,
    );
  });
});

describe('property: hybrid encryption', () => {
  it(
    'decrypt(encrypt(x)) deep-equals x for any payload',
    async () => {
      const pair = await pqc.keys.generate();
      await fc.assert(
        fc.asyncProperty(fc.uint8Array({ maxLength: 2048 }), async (payload) => {
          const plaintext = await pqc.decrypt(
            await pqc.encrypt(payload, pair.publicKey),
            pair.secretKey,
          );
          expect(bytesEqual(plaintext, payload)).toBe(true);
        }),
        kem,
      );
    },
    CRYPTO_TIMEOUT,
  );

  it(
    'any single-byte tamper fails closed — never returns plaintext',
    async () => {
      const pair = await pqc.keys.generate();
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 1, maxLength: 512 }),
          fc.nat(),
          fc.integer({ min: 1, max: 255 }),
          async (payload, indexSeed, xor) => {
            const ciphertext = await pqc.encrypt(payload, pair.publicKey);
            const index = indexSeed % ciphertext.length;
            const tampered = Uint8Array.from(ciphertext);
            // xor in [1,255] guarantees the byte actually changes.
            tampered[index] = tampered[index]! ^ xor;

            // The real security invariant: an authenticated scheme must throw on
            // ANY tamper and never return plaintext (right or wrong). The two
            // header bytes fail fast as INVALID_CIPHERTEXT; every other byte as
            // DECRYPTION_FAILED — both are documented fail-closed PqcError codes.
            const error = await pqc.decrypt(tampered, pair.secretKey).then(
              () => {
                throw new Error(`tamper at byte ${index} did not throw`);
              },
              (cause: unknown) => cause,
            );
            expect(error).toBeInstanceOf(PqcError);
            const code = (error as PqcError).code;
            expect(
              index < 2 ? ['INVALID_CIPHERTEXT', 'DECRYPTION_FAILED'] : ['DECRYPTION_FAILED'],
            ).toContain(code);
          },
        ),
        kem,
      );
    },
    CRYPTO_TIMEOUT,
  );
});

describe('property: signatures', () => {
  it(
    'verify accepts a genuine signature and rejects any single-byte tamper',
    async () => {
      const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 1, maxLength: 256 }),
          fc.nat(),
          fc.integer({ min: 1, max: 255 }),
          async (message, indexSeed, xor) => {
            const signature = await pqc.sign(message, pair.secretKey);
            expect(await pqc.verify(message, signature, pair.publicKey)).toBe(true);

            const tamperedSig = Uint8Array.from(signature);
            const sigIndex = indexSeed % signature.length;
            tamperedSig[sigIndex] = tamperedSig[sigIndex]! ^ xor;
            expect(await pqc.verify(message, tamperedSig, pair.publicKey)).toBe(false);

            const tamperedMsg = Uint8Array.from(message);
            const msgIndex = indexSeed % message.length;
            tamperedMsg[msgIndex] = tamperedMsg[msgIndex]! ^ xor;
            expect(await pqc.verify(tamperedMsg, signature, pair.publicKey)).toBe(false);
          },
        ),
        sig,
      );
    },
    CRYPTO_TIMEOUT,
  );
});
