import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

import { KEM_ALGORITHMS, requireKey } from './algorithms.js';
import { PqcError } from './errors.js';
import type { KemAlgorithm, PublicKey, SecretKey } from './types.js';

const NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

const utf8 = new TextEncoder();

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? utf8.encode(data) : data;
}

/**
 * Hybrid encryption: encapsulates a secret with the public key's KEM and
 * encrypts the data with AES-256-GCM using that secret. The result is a
 * single self-contained `Uint8Array` that only {@link decrypt} can open.
 *
 * The key chooses the envelope (docs/serialization-format.md §2): an
 * `ml-kem-768` key (FIPS 203) produces a v1 envelope, an `x-wing` key
 * (X25519 + ML-KEM-768 hybrid, draft-connolly-cfrg-xwing-kem-10) a v2 one.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate();
 * const ciphertext = await pqc.encrypt('sensitive data', pair.publicKey);
 *
 * const hybrid = await pqc.keys.generate({ algorithm: 'x-wing' });
 * const v2Ciphertext = await pqc.encrypt('sensitive data', hybrid.publicKey);
 * ```
 */
export async function encrypt(
  data: Uint8Array | string,
  publicKey: PublicKey<KemAlgorithm>,
): Promise<Uint8Array> {
  const spec = requireKey(publicKey, 'kem', 'public', 'encrypt');
  const plaintext = toBytes(data);

  // The KEM shared secret is the AES-256 key, verbatim, for both envelopes.
  // v1: the raw ML-KEM-768 shared secret (uniform per FIPS 203, no KDF).
  // v2: X-Wing's shared secret IS its §5.3 combiner output,
  // SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel) — a spec-defined
  // derivation with a fixed domain-separation label and binding to the
  // recipient public key (draft-connolly-cfrg-xwing-kem-10 §5.3). Adding
  // another KDF on top would be exactly the home-grown secret-mixing the
  // never-invent rule forbids; the combiner is the derivation.
  const { cipherText, sharedSecret } = spec.kem.encapsulate(publicKey.bytes);
  const nonce = randomBytes(NONCE_LENGTH);

  // Bind the 2-byte header (envelopeVersion, headerId) as AES-GCM additional
  // authenticated data so it is covered by the GCM tag (see decrypt).
  const header = new Uint8Array([spec.envelopeVersion, spec.headerId]);
  const sealed = gcm(sharedSecret, nonce, header).encrypt(plaintext);

  const out = new Uint8Array(2 + cipherText.length + nonce.length + sealed.length);
  out.set(header, 0);
  out.set(cipherText, 2);
  out.set(nonce, 2 + cipherText.length);
  out.set(sealed, 2 + cipherText.length + nonce.length);
  return Promise.resolve(out);
}

/**
 * Decrypts a ciphertext produced by {@link encrypt}, discriminating the
 * envelope on its leading version byte (`0x01` = ml-kem-768 v1, `0x02` =
 * x-wing v2; unknown versions fail with `INVALID_CIPHERTEXT`). If the
 * ciphertext was tampered with or the key does not match, it throws
 * {@link PqcError} with code `DECRYPTION_FAILED` — it never returns
 * corrupted data.
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
  secretKey: SecretKey<KemAlgorithm>,
): Promise<Uint8Array> {
  const spec = requireKey(secretKey, 'kem', 'secret', 'decrypt');

  if (ciphertext.length < 2) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Ciphertext is truncated or was not produced by pqc.encrypt',
    );
  }
  // This equality check is fail-fast input validation: it discriminates the
  // version and algorithm with a clear INVALID_CIPHERTEXT error before any
  // cryptographic work — covering unknown versions AND cross-version key
  // confusion (a v1 envelope offered to an x-wing key, or v2 to ml-kem-768).
  // The AAD binding below is the *cryptographic* integrity of the header —
  // a tampered-but-known header passing this check still fails the GCM tag.
  // Do not remove either guard in a refactor.
  if (ciphertext[0] !== spec.envelopeVersion || ciphertext[1] !== spec.headerId) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Unknown header: the ciphertext does not match this version or algorithm',
    );
  }

  const minLength = 2 + spec.ciphertextLength + NONCE_LENGTH + GCM_TAG_LENGTH;
  if (ciphertext.length < minLength) {
    throw new PqcError(
      'INVALID_CIPHERTEXT',
      'Ciphertext is truncated or was not produced by pqc.encrypt',
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

  // decapsulate stays inside the try: ML-KEM and X-Wing use implicit rejection
  // and do not throw for a valid-length secret key, but any edge case where
  // they (or GCM) throw must still surface as the documented
  // DECRYPTION_FAILED, never a raw upstream error.
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

/**
 * Names of the KEM algorithms `pqc.encrypt`/`pqc.decrypt` accept, for
 * introspection — e.g. validating a key file holds an encryption key rather
 * than a signing key, without hardcoding the list.
 *
 * @example
 * ```ts
 * import { KEM_NAMES } from '@pqc-sdk/core';
 *
 * KEM_NAMES.includes('x-wing'); // true
 * ```
 */
export const KEM_NAMES = Object.keys(KEM_ALGORITHMS);
