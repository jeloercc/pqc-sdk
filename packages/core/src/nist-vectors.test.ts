import { gcm } from '@noble/ciphers/aes.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';
import { generateKeyPairFromSeed } from './keys.js';
import mldsa44Keygen from './vectors/mldsa44-keygen.json';
import mldsa44Sigver from './vectors/mldsa44-sigver.json';
import mldsa65Keygen from './vectors/mldsa65-keygen.json';
import mldsa65Sigver from './vectors/mldsa65-sigver.json';
import mldsa87Keygen from './vectors/mldsa87-keygen.json';
import mldsa87Sigver from './vectors/mldsa87-sigver.json';
import mlkemEncapDecap from './vectors/mlkem768-encapdecap.json';
import mlkemKeygen from './vectors/mlkem768-keygen.json';

const utf8 = new TextEncoder();

/**
 * Builds an SDK hybrid ciphertext from a NIST-expected KEM ciphertext and
 * shared secret. If pqc.decrypt recovers the plaintext, our pipeline's
 * decapsulation produces exactly the vector's secret.
 */
function buildHybridCiphertext(kemCiphertext: Uint8Array, sharedSecret: Uint8Array) {
  const plaintext = utf8.encode('vector check');
  const nonce = new Uint8Array(12).fill(7);
  // The 2-byte header is bound as AES-GCM additional data, mirroring pqc.encrypt.
  const header = new Uint8Array([1, 1]); // format version, ml-kem-768 header id
  const sealed = gcm(sharedSecret, nonce, header).encrypt(plaintext);
  const out = new Uint8Array(2 + kemCiphertext.length + nonce.length + sealed.length);
  out.set(header, 0);
  out.set(kemCiphertext, 2);
  out.set(nonce, 2 + kemCiphertext.length);
  out.set(sealed, 2 + kemCiphertext.length + nonce.length);
  return { ciphertext: out, plaintext };
}

describe('NIST ACVP ML-KEM-768 keyGen (FIPS 203)', () => {
  it.each(mlkemKeygen.cases)(
    'tcId $tcId: seed d||z produces the expected ek/dk',
    ({ d, z, ek, dk }) => {
      const seed = new Uint8Array([...hexToBytes(d), ...hexToBytes(z)]);
      const pair = generateKeyPairFromSeed('ml-kem-768', seed);

      expect(Buffer.from(pair.publicKey.bytes).toString('hex')).toBe(ek.toLowerCase());
      expect(Buffer.from(pair.secretKey.bytes).toString('hex')).toBe(dk.toLowerCase());
    },
  );
});

describe('NIST ACVP ML-KEM-768 encapDecap (FIPS 203)', () => {
  it.each(mlkemEncapDecap.encapsulation)(
    'encapsulation tcId $tcId: decrypt recovers the expected shared secret',
    async ({ dk, c, k }) => {
      const secretKey = pqc.keys.deserialize(
        `pqcv1.ml-kem-768.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
        { algorithm: 'ml-kem-768', use: 'secret' },
      );
      const { ciphertext, plaintext } = buildHybridCiphertext(hexToBytes(c), hexToBytes(k));

      const result = await pqc.decrypt(ciphertext, secretKey);

      expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
    },
  );

  it.each(mlkemEncapDecap.decapsulation)(
    'decapsulation tcId $tcId: decrypt recovers the expected shared secret',
    async ({ dk, c, k }) => {
      const secretKey = pqc.keys.deserialize(
        `pqcv1.ml-kem-768.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
        { algorithm: 'ml-kem-768', use: 'secret' },
      );
      const { ciphertext, plaintext } = buildHybridCiphertext(hexToBytes(c), hexToBytes(k));

      const result = await pqc.decrypt(ciphertext, secretKey);

      expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
    },
  );
});

// One block per FIPS 204 parameter set. All three vector files come from the
// same NIST ACVP-Server source as the original ml-dsa-65 files (see each
// JSON's "source" field) — see docs/compliance/FIPS-204-MATRIX.md §3.1 for
// the F204-01 closure this evidence supports.
const ML_DSA_SETS = [
  { algorithm: 'ml-dsa-44' as const, keygen: mldsa44Keygen, sigver: mldsa44Sigver },
  { algorithm: 'ml-dsa-65' as const, keygen: mldsa65Keygen, sigver: mldsa65Sigver },
  { algorithm: 'ml-dsa-87' as const, keygen: mldsa87Keygen, sigver: mldsa87Sigver },
];

for (const { algorithm, keygen, sigver } of ML_DSA_SETS) {
  describe(`NIST ACVP ${algorithm.toUpperCase()} keyGen (FIPS 204)`, () => {
    it.each(keygen.cases)('tcId $tcId: seed produces the expected pk/sk', ({ seed, pk, sk }) => {
      const pair = generateKeyPairFromSeed(algorithm, hexToBytes(seed));

      expect(Buffer.from(pair.publicKey.bytes).toString('hex')).toBe(pk.toLowerCase());
      expect(Buffer.from(pair.secretKey.bytes).toString('hex')).toBe(sk.toLowerCase());
    });
  });

  describe(`NIST ACVP ${algorithm.toUpperCase()} sigVer (FIPS 204, pure)`, () => {
    it.each(sigver.cases)(
      'tcId $tcId: verify returns $testPassed ($reason)',
      async ({ pk, message, context, signature, testPassed }) => {
        const publicKey = pqc.keys.deserialize(
          `pqcv1.${algorithm}.public.${Buffer.from(hexToBytes(pk)).toString('base64url')}`,
          { algorithm, use: 'public' },
        );

        const result = await pqc.verify(hexToBytes(message), hexToBytes(signature), publicKey, {
          context: hexToBytes(context),
        });

        expect(result).toBe(testPassed);
      },
    );
  });
}
