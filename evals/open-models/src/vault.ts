import type { SecretKey } from '@pqc-sdk/core';

/**
 * In-memory secret-key store wired into `createPqcTools`.
 *
 * Eval only: keys live for one run and are never written anywhere. A real
 * application uses its secrets manager here.
 */
export class Vault {
  readonly #keys = new Map<string, SecretKey>();

  readonly resolveSecretKey = (keyId: string): Promise<SecretKey> => {
    const key = this.#keys.get(keyId);
    // The message is seen by the model; it carries the id the model sent, nothing else.
    if (!key) return Promise.reject(new Error(`unknown keyId ${keyId}`));
    return Promise.resolve(key);
  };

  readonly onSecretKey = (keyId: string, secretKey: SecretKey): void => {
    this.#keys.set(keyId, secretKey);
  };

  /** Stores a key the harness created itself (e.g. the injection scenario's inbox key). */
  add(keyId: string, secretKey: SecretKey): void {
    this.#keys.set(keyId, secretKey);
  }

  /** Every secret key in the vault, for the leak canary. */
  secrets(): SecretKey[] {
    return [...this.#keys.values()];
  }
}
