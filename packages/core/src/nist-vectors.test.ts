import { gcm } from '@noble/ciphers/aes.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';
import { generateKeyPairFromSeed } from './keys.js';
import mldsaKeygen from './vectors/mldsa65-keygen.json';
import mldsaSigver from './vectors/mldsa65-sigver.json';
import mlkemEncapDecap from './vectors/mlkem768-encapdecap.json';
import mlkemKeygen from './vectors/mlkem768-keygen.json';

const utf8 = new TextEncoder();

/**
 * Construye un ciphertext híbrido del SDK a partir de un KEM ciphertext y un
 * shared secret esperados por NIST. Si pqc.decrypt recupera el plaintext, la
 * decapsulación de nuestro pipeline produce exactamente el secret del vector.
 */
function buildHybridCiphertext(kemCiphertext: Uint8Array, sharedSecret: Uint8Array) {
  const plaintext = utf8.encode('vector check');
  const nonce = new Uint8Array(12).fill(7);
  const sealed = gcm(sharedSecret, nonce).encrypt(plaintext);
  const out = new Uint8Array(2 + kemCiphertext.length + nonce.length + sealed.length);
  out[0] = 1; // versión de formato
  out[1] = 1; // id de ml-kem-768
  out.set(kemCiphertext, 2);
  out.set(nonce, 2 + kemCiphertext.length);
  out.set(sealed, 2 + kemCiphertext.length + nonce.length);
  return { ciphertext: out, plaintext };
}

describe('NIST ACVP ML-KEM-768 keyGen (FIPS 203)', () => {
  it.each(mlkemKeygen.cases)(
    'tcId $tcId: seed d||z produce ek/dk esperados',
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
    'encapsulation tcId $tcId: decrypt recupera el shared secret esperado',
    async ({ dk, c, k }) => {
      const secretKey = pqc.keys.deserialize(
        `pqcv1.ml-kem-768.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
      );
      const { ciphertext, plaintext } = buildHybridCiphertext(hexToBytes(c), hexToBytes(k));

      const result = await pqc.decrypt(ciphertext, secretKey as never);

      expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
    },
  );

  it.each(mlkemEncapDecap.decapsulation)(
    'decapsulation tcId $tcId: decrypt recupera el shared secret esperado',
    async ({ dk, c, k }) => {
      const secretKey = pqc.keys.deserialize(
        `pqcv1.ml-kem-768.secret.${Buffer.from(hexToBytes(dk)).toString('base64url')}`,
      );
      const { ciphertext, plaintext } = buildHybridCiphertext(hexToBytes(c), hexToBytes(k));

      const result = await pqc.decrypt(ciphertext, secretKey as never);

      expect(Buffer.from(result).equals(Buffer.from(plaintext))).toBe(true);
    },
  );
});

describe('NIST ACVP ML-DSA-65 keyGen (FIPS 204)', () => {
  it.each(mldsaKeygen.cases)('tcId $tcId: seed produce pk/sk esperados', ({ seed, pk, sk }) => {
    const pair = generateKeyPairFromSeed('ml-dsa-65', hexToBytes(seed));

    expect(Buffer.from(pair.publicKey.bytes).toString('hex')).toBe(pk.toLowerCase());
    expect(Buffer.from(pair.secretKey.bytes).toString('hex')).toBe(sk.toLowerCase());
  });
});

describe('NIST ACVP ML-DSA-65 sigVer (FIPS 204, pure)', () => {
  it.each(mldsaSigver.cases)(
    'tcId $tcId: verify devuelve $testPassed ($reason)',
    async ({ pk, message, context, signature, testPassed }) => {
      const publicKey = pqc.keys.deserialize(
        `pqcv1.ml-dsa-65.public.${Buffer.from(hexToBytes(pk)).toString('base64url')}`,
      );

      const result = await pqc.verify(
        hexToBytes(message),
        hexToBytes(signature),
        publicKey as never,
        {
          context: hexToBytes(context),
        },
      );

      expect(result).toBe(testPassed);
    },
  );
});
