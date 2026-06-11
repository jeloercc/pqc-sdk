import { randomBytes } from '@noble/post-quantum/utils.js';

import { getAlgorithm, keyLengthFor } from './algorithms.js';
import { fromBase64Url, toBase64Url } from './base64url.js';
import { PqcError } from './errors.js';
import type { Algorithm, KeyPair, PqcKey } from './types.js';

const SERIAL_PREFIX = 'pqcv1';

/** Opciones de {@link generate}. */
export interface GenerateOptions<A extends Algorithm = Algorithm> {
  /** Algoritmo del par. Default: `'ml-kem-768'` (cifrado). */
  readonly algorithm?: A;
}

/**
 * Genera un par de keys post-cuánticas. Sin opciones genera ML-KEM-768,
 * listo para `pqc.encrypt`.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const encryption = await pqc.keys.generate();
 * const signing = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * ```
 */
export async function generate(): Promise<KeyPair<'ml-kem-768'>>;
export async function generate<A extends Algorithm>(
  options: GenerateOptions<A> & { algorithm: A },
): Promise<KeyPair<A>>;
export async function generate(options?: GenerateOptions): Promise<KeyPair>;
export async function generate(options?: GenerateOptions): Promise<KeyPair> {
  const algorithm = options?.algorithm ?? 'ml-kem-768';
  const spec = getAlgorithm(algorithm);
  return Promise.resolve(generateKeyPairFromSeed(algorithm, randomBytes(spec.seedLength)));
}

/**
 * Generación determinística a partir de una seed. Uso interno y de tests
 * (vectores NIST). Para uso normal preferir {@link generate}.
 */
export function generateKeyPairFromSeed(algorithm: Algorithm, seed: Uint8Array): KeyPair {
  const spec = getAlgorithm(algorithm);
  if (seed.length !== spec.seedLength) {
    throw new PqcError(
      'INVALID_KEY',
      `Seed de ${algorithm} debe medir ${spec.seedLength} bytes, recibió ${seed.length}`,
    );
  }
  const material = spec.kind === 'kem' ? spec.kem.keygen(seed) : spec.signer.keygen(seed);
  return {
    algorithm,
    publicKey: { algorithm, use: 'public', bytes: material.publicKey },
    secretKey: { algorithm, use: 'secret', bytes: material.secretKey },
  };
}

/**
 * Serializa una key a un string portable: `pqcv1.<algoritmo>.<uso>.<base64url>`.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate();
 * const token = pqc.keys.serialize(pair.publicKey);
 * // "pqcv1.ml-kem-768.public.h1q3…"
 * ```
 */
export function serialize(key: PqcKey): string {
  const spec = getAlgorithm(key.algorithm);
  if (key.bytes.length !== keyLengthFor(spec, key.use)) {
    throw new PqcError('INVALID_KEY', `Key ${key.algorithm} ${key.use} con longitud inválida`);
  }
  return `${SERIAL_PREFIX}.${key.algorithm}.${key.use}.${toBase64Url(key.bytes)}`;
}

/**
 * Reconstruye una key desde el formato de {@link serialize}. Valida versión,
 * algoritmo, uso y longitud; ante cualquier problema lanza {@link PqcError}
 * con código `INVALID_SERIALIZED_KEY` o `INVALID_KEY`.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const publicKey = pqc.keys.deserialize(tokenRecibidoDelCliente);
 * const ciphertext = await pqc.encrypt(payload, publicKey);
 * ```
 */
export function deserialize(serialized: string): PqcKey {
  const parts = serialized.split('.');
  if (parts.length !== 4 || parts[0] !== SERIAL_PREFIX) {
    throw new PqcError(
      'INVALID_SERIALIZED_KEY',
      'Formato esperado: pqcv1.<algoritmo>.<uso>.<base64url>',
    );
  }
  const [, algorithm, use, encoded] = parts as [string, string, string, string];
  const spec = getAlgorithm(algorithm);
  if (use !== 'public' && use !== 'secret') {
    throw new PqcError('INVALID_SERIALIZED_KEY', `Uso de key desconocido: ${use}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(encoded);
  } catch (cause) {
    throw new PqcError(
      'INVALID_SERIALIZED_KEY',
      cause instanceof Error ? cause.message : 'base64url inválido',
    );
  }
  const key: PqcKey = { algorithm: algorithm as Algorithm, use, bytes };
  if (bytes.length !== keyLengthFor(spec, key.use)) {
    throw new PqcError(
      'INVALID_KEY',
      `Key ${algorithm} ${use} debe medir ${keyLengthFor(spec, key.use)} bytes, midió ${bytes.length}`,
    );
  }
  return key;
}
