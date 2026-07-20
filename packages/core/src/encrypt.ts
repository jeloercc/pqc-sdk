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
  // x-wing keys exist since Day 1 of the hybrid sprint, but their envelope is
  // the not-yet-implemented pqcenc.v2: fail closed rather than emit an
  // unspecified format. Removed when the v2 envelope lands.
  if ((publicKey.algorithm as string) !== 'ml-kem-768') {
    throw new PqcError(
      'UNSUPPORTED_ALGORITHM',
      `encrypt supports ml-kem-768 envelopes only for now; the ${publicKey.algorithm} envelope format (v2) is not implemented yet`,
    );
  }
  const plaintext = toBytes(data);

  const { cipherText, sharedSecret } = spec.kem.encapsulate(publicKey.bytes);
  const nonce = randomBytes(NONCE_LENGTH);

  // Bind the 2-byte header (FORMAT_VERSION, headerId) as AES-GCM additional
  // authenticated data so it is covered by the GCM tag (see decrypt).
  const header = new Uint8Array([FORMAT_VERSION, spec.headerId]);
  const sealed = gcm(sharedSecret, nonce, header).encrypt(plaintext);

  const out = new Uint8Array(2 + cipherText.length + nonce.length + sealed.length);
  out.set(header, 0);
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
  // Mirror of the encrypt guard: no v2 envelopes exist yet to decrypt.
  if ((secretKey.algorithm as string) !== 'ml-kem-768') {
    throw new PqcError(
      'UNSUPPORTED_ALGORITHM',
      `decrypt supports ml-kem-768 envelopes only for now; the ${secretKey.algorithm} envelope format (v2) is not implemented yet`,
    );
  }

  const minLength = 2 + spec.ciphertextLength + NONCE_LENGTH + GCM_TAG_LENGTH;
  if (ciphertext.length < minLength) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Ciphertext is truncated or was not produced by pqc.encrypt',
    );
  }
  // This equality check is fail-fast input validation: it discriminates the
  // version and algorithm with a clear INVALID_CIPHERTEXT error before any
  // cryptographic work. The AAD binding below is the *cryptographic* integrity
  // of the header — it becomes the only line of defence once more versions or
  // algorithms share this layout (a tampered-but-known header would pass this
  // check yet fail the GCM tag). Do not remove either guard in a refactor.
  if (ciphertext[0] !== FORMAT_VERSION || ciphertext[1] !== spec.headerId) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Unknown header: the ciphertext does not match this version or algorithm',
    );
  }

  // Reconstruct the AAD from the header bytes actually present in the message
  // so AES-GCM authenticates them as part of the tag.
  const header = ciphertext.subarray(0, 2);
  const kemCiphertext = ciphertext.subarray(2, 2 + spec.ciphertextLength);
  const nonce = ciphertext.subarray(
    2 + spec.ciphertextLength,
    2 + spec.ciphertextLength + NONCE_LENGTH,
  );
  const sealed = ciphertext.subarray(2 + spec.ciphertextLength + NONCE_LENGTH);

  // decapsulate stays inside the try: ML-KEM uses implicit rejection and does
  // not throw for a valid-length secret key, but any edge case where it (or GCM)
  // throws must still surface as the documented DECRYPTION_FAILED, never a raw
  // upstream error.
  try {
    const sharedSecret = spec.kem.decapsulate(kemCiphertext, secretKey.bytes);
    return Promise.resolve(gcm(sharedSecret, nonce, header).decrypt(sealed));
  } catch (cause) {
    if (cause instanceof PqcError) {
      throw cause;
    }
    throw new PqcError(
      'DECRYPTION_FAILED',
      'Decryption failed: tampered ciphertext or wrong secret key',
    );
  }
}

/** Available KEM algorithms, exported for introspection. */
export const KEM_NAMES = Object.keys(KEM_ALGORITHMS);
