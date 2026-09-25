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
import mlkem512EncapDecap from './vectors/mlkem512-encapdecap.json';
import mlkem512Keygen from './vectors/mlkem512-keygen.json';
import mlkem768EncapDecap from './vectors/mlkem768-encapdecap.json';
import mlkem768Keygen from './vectors/mlkem768-keygen.json';
import mlkem1024EncapDecap from './vectors/mlkem1024-encapdecap.json';
import mlkem1024Keygen from './vectors/mlkem1024-keygen.json';

const utf8 = new TextEncoder();

/**
 * Builds an SDK hybrid ciphertext from a KEM ciphertext and shared secret,
 * using the given envelope version and header id (docs/serialization-format.md §2).
 * If pqc.decrypt recovers the plaintext, our pipeline's decapsulation produces
 * exactly the vector's shared secret.
 */
function buildHybridCiphertext(
  kemCiphertext: Uint8Array,
  sharedSecret: Uint8Array,
  envelopeVersion: number,
  headerId: number,
) {
  const plaintext = utf8.encode('vector check');
  const nonce = new Uint8Array(12).fill(7);
  const header = new Uint8Array([envelopeVersion, headerId]);
  const sealed = gcm(sharedSecret, nonce, header).encrypt(plaintext);
  const out = new Uint8Array(2 + kemCiphertext.length + nonce.length + sealed.length);
  out.set(header, 0);
  out.set(kemCiphertext, 2);
  out.set(nonce, 2 + kemCiphertext.length);
  out.set(sealed, 2 + kemCiphertext.length + nonce.length);
  return { ciphertext: out, plaintext };
}

// All three FIPS 203 ML-KEM parameter sets, parametrized.
// envelopeVersion and headerId per docs/serialization-format.md §2.
const ML_KEM_SETS = [
  {
    algorithm: 'ml-kem-512' as const,
    envelopeVersion: 3,
    headerId: 3,
    keygen: mlkem512Keygen,
    encapDecap: mlkem512EncapDecap,
  },
  {
    algorithm: 'ml-kem-768' as const,
    envelopeVersion: 1,
    headerId: 1,
    keygen: mlkem768Keygen,
    encapDecap: mlkem768EncapDecap,
  },
  {
    algorithm: 'ml-kem-1024' as const,
    envelopeVersion: 4,
    headerId: 4,
    keygen: mlkem1024Keygen,
    encapDecap: mlkem1024EncapDecap,
  },
];

for (const { algorithm, envelopeVersion, headerId, keygen, encapDecap } of ML_KEM_SETS) {
  describe(`FIPS 203 ${algorithm.toUpperCase()} keyGen`, () => {
    it.each(keygen.cases)(
      'tcId $tcId: seed d||z produces the expected ek/dk',
      ({ d, z, ek, dk }) => {
        const seed = new Uint8Array([...hexToBytes(d), ...hexToBytes(z)]);
        const pair = generateKeyPairFromSeed(algorithm, seed);

        expect(Buffer.from(pair.publicKey.bytes).toString('hex')).toBe(ek.toLowerCase());
        expect(Buffer.from(pair.secretKey.bytes).toString('hex')).toBe(dk.toLowerCase());
      },
    );
  });

  describe(`FIPS 203 ${algorithm.toUpperCase()} encapDecap`, () => {
    it.each(encapDecap.encapsulation)(
      'encapsulation tcId $tcId: decrypt recovers the expected shared secret',
      async ({ dk, c, k }) => {
        const secretKey = pqc.keys.deserialize(
          `pqcv1.${algorithm}.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
          { algorithm, use: 'secret' },
        );
        const { ciphertext, plaintext } = buildHybridCiphertext(
          hexToBytes(c),
          hexToBytes(k),
          envelopeVersion,
          headerId,
        );

        const result = await pqc.decrypt(ciphertext, secretKey);

        expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
      },
    );

    it.each(encapDecap.decapsulation)(
      'decapsulation tcId $tcId: decrypt recovers the expected shared secret',
      async ({ dk, c, k }) => {
        const secretKey = pqc.keys.deserialize(
          `pqcv1.${algorithm}.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
          { algorithm, use: 'secret' },
        );
        const { ciphertext, plaintext } = buildHybridCiphertext(
          hexToBytes(c),
          hexToBytes(k),
          envelopeVersion,
          headerId,
        );

        const result = await pqc.decrypt(ciphertext, secretKey);

        expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
      },
    );
  });
}

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
