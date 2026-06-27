/** Error codes the SDK can emit. */
export type PqcErrorCode =
  | 'UNSUPPORTED_ALGORITHM'
  | 'WRONG_ALGORITHM'
  | 'WRONG_KEY_USE'
  | 'INVALID_KEY'
  | 'INVALID_SERIALIZED_KEY'
  | 'INVALID_CONTEXT'
  | 'INVALID_CIPHERTEXT'
  | 'DECRYPTION_FAILED';

/**
 * Typed SDK error. Every expected failure exposes a stable `code` so it can
 * be handled programmatically without parsing messages.
 *
 * @example
 * ```ts
 * import { PqcError, pqc } from '@pqc-sdk/core';
 *
 * try {
 *   await pqc.decrypt(ciphertext, secretKey);
 * } catch (error) {
 *   if (error instanceof PqcError && error.code === 'DECRYPTION_FAILED') {
 *     // tampered ciphertext or wrong key
 *   }
 * }
 * ```
 */
export class PqcError extends Error {
  readonly code: PqcErrorCode;

  constructor(code: PqcErrorCode, message: string) {
    super(message);
    this.name = 'PqcError';
    this.code = code;
  }
}
