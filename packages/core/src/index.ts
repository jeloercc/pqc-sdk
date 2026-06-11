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

/**
 * Versión del SDK.
 *
 * @example
 * ```ts
 * import { version } from '@pqc-sdk/core';
 *
 * console.log(version); // "0.0.1"
 * ```
 */
export const version = '0.0.1';

/**
 * Algoritmos PQC implementados (FIPS 203 y FIPS 204).
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
 * Punto de entrada del SDK: cifrado híbrido post-cuántico y firmas digitales
 * con defaults seguros, sin configuración.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * // Cifrado (ML-KEM-768 + AES-256-GCM)
 * const pair = await pqc.keys.generate();
 * const ciphertext = await pqc.encrypt('hola', pair.publicKey);
 * const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
 *
 * // Firmas (ML-DSA-65)
 * const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign('documento', signer.secretKey);
 * await pqc.verify('documento', signature, signer.publicKey); // true
 * ```
 */
export const pqc = {
  keys: { generate, serialize, deserialize },
  encrypt,
  decrypt,
  sign,
  verify,
} as const;
