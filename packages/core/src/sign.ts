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
 * Firma datos con ML-DSA-65 (FIPS 204), modo hedged (firma aleatorizada,
 * el default del estándar). Devuelve la firma de 3309 bytes.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign(documento, pair.secretKey);
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
 * Verifica una firma ML-DSA-65. Devuelve `false` ante firmas inválidas o
 * malformadas (nunca lanza por una firma corrupta); solo lanza si la key
 * no es ML-DSA.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const valid = await pqc.verify(documento, signature, pair.publicKey);
 * if (!valid) throw new Error('firma inválida');
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
