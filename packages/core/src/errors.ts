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

/**
 * Bounds a value taken from untrusted input (a serialized-key segment, an
 * algorithm name from a file) before echoing it in an error message, so a
 * malformed input cannot inject unbounded content into errors that end up in
 * logs. Internal — not part of the public API.
 *
 * @example
 * ```ts
 * import { truncateForError } from './errors.js';
 *
 * truncateForError('ml-kem-768'); // 'ml-kem-768'
 * truncateForError('x'.repeat(100)); // first 32 chars followed by '…'
 * ```
 */
export function truncateForError(value: string, maxLength = 32): string {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength)}…`;
}
