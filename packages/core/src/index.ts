import { encrypt, decrypt } from './encrypt.js';
import { deserialize, generate, serialize } from './keys.js';
import { sign, verify } from './sign.js';

export { PqcError, type PqcErrorCode } from './errors.js';
export { KEM_NAMES } from './encrypt.js';
export type { ExpectedKey, GenerateOptions } from './keys.js';
export type {
  Algorithm,
  KemAlgorithm,
  KeyPair,
  KeyUse,
  PqcKey,
  PublicKey,
  SecretKey,
  SignatureAlgorithm,
  SignatureOptions,
} from './types.js';
export { encrypt, decrypt, sign, verify, generate, serialize, deserialize };

// Injected at build time from package.json (`define` in tsup.config.ts and vitest.config.ts).
declare const __PQC_CORE_VERSION__: string;

/**
 * SDK version.
 *
 * @example
 * ```ts
 * import { version } from '@pqc-sdk/core';
 *
 * console.log(version); // e.g. "0.1.0"
 * ```
 */
export const version = __PQC_CORE_VERSION__;

/**
 * Implemented PQC algorithms (FIPS 203, FIPS 204, and the X-Wing hybrid KEM
 * from draft-connolly-cfrg-xwing-kem-10).
 *
 * @example
 * ```ts
 * import { SUPPORTED_ALGORITHMS } from '@pqc-sdk/core';
 *
 * SUPPORTED_ALGORITHMS.includes('ml-kem-768'); // true
 * SUPPORTED_ALGORITHMS.includes('x-wing'); // true
 * ```
 */
export const SUPPORTED_ALGORITHMS = ['ml-kem-768', 'ml-dsa-65', 'x-wing'] as const;

export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/**
 * SDK entry point: post-quantum hybrid encryption and digital signatures
 * with safe defaults, zero configuration.
 *
 * `keys.generate()` with no arguments still returns `ml-kem-768` (the
 * `pqcenc.v1` envelope); pass `{ algorithm: 'x-wing' }` for the classical+PQC
 * hybrid KEM (X25519 + ML-KEM-768, `pqcenc.v2` envelope) recommended for
 * long-term data — see the "Choosing an algorithm" guide. The no-arg default
 * changes to `x-wing` at v1.0.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * // Encryption (ML-KEM-768 + AES-256-GCM)
 * const pair = await pqc.keys.generate();
 * const ciphertext = await pqc.encrypt('hello', pair.publicKey);
 * const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
 *
 * // Hybrid encryption (X-Wing: X25519 + ML-KEM-768 + AES-256-GCM)
 * const hybrid = await pqc.keys.generate({ algorithm: 'x-wing' });
 * const hybridCiphertext = await pqc.encrypt('hello', hybrid.publicKey);
 * const hybridPlaintext = await pqc.decrypt(hybridCiphertext, hybrid.secretKey);
 *
 * // Signatures (ML-DSA-65)
 * const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign('document', signer.secretKey);
 * await pqc.verify('document', signature, signer.publicKey); // true
 * ```
 */
export const pqc = {
  keys: { generate, serialize, deserialize },
  encrypt,
  decrypt,
  sign,
  verify,
} as const;
