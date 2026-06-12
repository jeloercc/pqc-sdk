import { encrypt, decrypt } from './encrypt.js';
import { deserialize, generate, serialize } from './keys.js';
import { sign, verify } from './sign.js';

export { PqcError, type PqcErrorCode } from './errors.js';
export type { GenerateOptions } from './keys.js';
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
 * Implemented PQC algorithms (FIPS 203 and FIPS 204).
 *
 * @example
 * ```ts
 * import { SUPPORTED_ALGORITHMS } from '@pqc-sdk/core';
 *
 * SUPPORTED_ALGORITHMS.includes('ml-kem-768'); // true
 * ```
 */
export const SUPPORTED_ALGORITHMS = ['ml-kem-768', 'ml-dsa-65'] as const;

export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/**
 * SDK entry point: post-quantum hybrid encryption and digital signatures
 * with safe defaults, zero configuration.
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
