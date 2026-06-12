import { requireKey } from './algorithms.js';
import type { PublicKey, SecretKey, SignatureOptions } from './types.js';

const utf8 = new TextEncoder();

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? utf8.encode(data) : data;
}

function toNobleOptions(options?: SignatureOptions): { context: Uint8Array } | undefined {
  return options?.context ? { context: options.context } : undefined;
}

/**
 * Signs data with ML-DSA-65 (FIPS 204) in hedged mode (randomized signing,
 * the standard's default). Returns the 3309-byte signature.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign(document, pair.secretKey);
 * ```
 */
export async function sign(
  data: Uint8Array | string,
  secretKey: SecretKey<'ml-dsa-65'>,
  options?: SignatureOptions,
): Promise<Uint8Array> {
  const spec = requireKey(secretKey, 'signer', 'secret', 'sign');
  return Promise.resolve(spec.signer.sign(toBytes(data), secretKey.bytes, toNobleOptions(options)));
}

/**
 * Verifies an ML-DSA-65 signature. Returns `false` for invalid or malformed
 * signatures (it never throws because of a corrupted signature); it only
 * throws if the key is not ML-DSA.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const valid = await pqc.verify(document, signature, pair.publicKey);
 * if (!valid) throw new Error('invalid signature');
 * ```
 */
export async function verify(
  data: Uint8Array | string,
  signature: Uint8Array,
  publicKey: PublicKey<'ml-dsa-65'>,
  options?: SignatureOptions,
): Promise<boolean> {
  const spec = requireKey(publicKey, 'signer', 'public', 'verify');
  try {
    return Promise.resolve(
      spec.signer.verify(signature, toBytes(data), publicKey.bytes, toNobleOptions(options)),
    );
  } catch {
    return false;
  }
}
