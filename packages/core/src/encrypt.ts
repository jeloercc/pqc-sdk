import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { KEM_ALGORITHMS, requireKey } from './algorithms.js';
import { PqcError } from './errors.js';
import type { PublicKey, SecretKey } from './types.js';

const FORMAT_VERSION = 1;
const NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

const utf8 = new TextEncoder();

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? utf8.encode(data) : data;
}

/**
 * Hybrid encryption: encapsulates a secret with ML-KEM-768 (FIPS 203) and
 * encrypts the data with AES-256-GCM using that secret. The result is a
 * single self-contained `Uint8Array` that only {@link decrypt} can open.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate();
 * const ciphertext = await pqc.encrypt('sensitive data', pair.publicKey);
 * ```
 */
export async function encrypt(
  data: Uint8Array | string,
  publicKey: PublicKey<'ml-kem-768'>,
): Promise<Uint8Array> {
  const spec = requireKey(publicKey, 'kem', 'public', 'encrypt');
  const plaintext = toBytes(data);

  const { cipherText, sharedSecret } = spec.kem.encapsulate(publicKey.bytes);
  const nonce = randomBytes(NONCE_LENGTH);
  const sealed = gcm(sharedSecret, nonce).encrypt(plaintext);

  const out = new Uint8Array(2 + cipherText.length + nonce.length + sealed.length);
  out[0] = FORMAT_VERSION;
  out[1] = spec.headerId;
  out.set(cipherText, 2);
  out.set(nonce, 2 + cipherText.length);
  out.set(sealed, 2 + cipherText.length + nonce.length);
  return Promise.resolve(out);
}

/**
 * Decrypts a ciphertext produced by {@link encrypt}. If the ciphertext was
 * tampered with or the key does not match, it throws {@link PqcError} with
 * code `DECRYPTION_FAILED` — it never returns corrupted data.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
 * new TextDecoder().decode(plaintext);
 * ```
 */
export async function decrypt(
  ciphertext: Uint8Array,
  secretKey: SecretKey<'ml-kem-768'>,
): Promise<Uint8Array> {
  const spec = requireKey(secretKey, 'kem', 'secret', 'decrypt');

  const minLength = 2 + spec.ciphertextLength + NONCE_LENGTH + GCM_TAG_LENGTH;
  if (ciphertext.length < minLength) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Ciphertext is truncated or was not produced by pqc.encrypt',
    );
  }
  if (ciphertext[0] !== FORMAT_VERSION || ciphertext[1] !== spec.headerId) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Unknown header: the ciphertext does not match this version or algorithm',
    );
  }

  const kemCiphertext = ciphertext.subarray(2, 2 + spec.ciphertextLength);
  const nonce = ciphertext.subarray(
    2 + spec.ciphertextLength,
    2 + spec.ciphertextLength + NONCE_LENGTH,
  );
  const sealed = ciphertext.subarray(2 + spec.ciphertextLength + NONCE_LENGTH);

  const sharedSecret = spec.kem.decapsulate(kemCiphertext, secretKey.bytes);
  try {
    return Promise.resolve(gcm(sharedSecret, nonce).decrypt(sealed));
  } catch {
    throw new PqcError(
      'DECRYPTION_FAILED',
      'Decryption failed: tampered ciphertext or wrong secret key',
    );
  }
}

/** Available KEM algorithms, exported for introspection. */
export const KEM_NAMES = Object.keys(KEM_ALGORITHMS);
