/** Códigos de error que puede emitir el SDK. */
export type PqcErrorCode =
  | 'UNSUPPORTED_ALGORITHM'
  | 'WRONG_ALGORITHM'
  | 'WRONG_KEY_USE'
  | 'INVALID_KEY'
  | 'INVALID_SERIALIZED_KEY'
  | 'INVALID_CIPHERTEXT'
  | 'DECRYPTION_FAILED';

/**
 * Error tipado del SDK. Toda falla esperable expone un `code` estable para
 * manejarla programáticamente sin parsear mensajes.
 *
 * @example
 * ```ts
 * import { PqcError, pqc } from '@pqc-sdk/core';
 *
 * try {
 *   await pqc.decrypt(ciphertext, secretKey);
 * } catch (error) {
 *   if (error instanceof PqcError && error.code === 'DECRYPTION_FAILED') {
 *     // ciphertext manipulado o key incorrecta
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
