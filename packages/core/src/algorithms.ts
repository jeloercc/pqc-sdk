import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { PqcError } from './errors.js';
import type { Algorithm, KemAlgorithm, KeyUse, PqcKey, SignatureAlgorithm } from './types.js';

interface AlgorithmSpec {
  readonly seedLength: number;
  readonly publicKeyLength: number;
  readonly secretKeyLength: number;
}

export interface KemSpec extends AlgorithmSpec {
  readonly kind: 'kem';
  readonly headerId: number;
  readonly ciphertextLength: number;
  readonly kem: typeof ml_kem768;
}

export interface SignerSpec extends AlgorithmSpec {
  readonly kind: 'signer';
  readonly signatureLength: number;
  readonly signer: typeof ml_dsa65;
}

export const KEM_ALGORITHMS: Record<KemAlgorithm, KemSpec> = {
  'ml-kem-768': {
    kind: 'kem',
    headerId: 1,
    kem: ml_kem768,
    seedLength: 64,
    publicKeyLength: 1184,
    secretKeyLength: 2400,
    ciphertextLength: 1088,
  },
};

export const SIGNATURE_ALGORITHMS: Record<SignatureAlgorithm, SignerSpec> = {
  'ml-dsa-65': {
    kind: 'signer',
    signer: ml_dsa65,
    seedLength: 32,
    publicKeyLength: 1952,
    secretKeyLength: 4032,
    signatureLength: 3309,
  },
};

export const ALGORITHMS: Record<Algorithm, KemSpec | SignerSpec> = {
  ...KEM_ALGORITHMS,
  ...SIGNATURE_ALGORITHMS,
};

export function getAlgorithm(algorithm: string): KemSpec | SignerSpec {
  const spec = (ALGORITHMS as Record<string, KemSpec | SignerSpec>)[algorithm];
  if (!spec) {
    throw new PqcError('UNSUPPORTED_ALGORITHM', `Algoritmo no soportado: ${algorithm}`);
  }
  return spec;
}

export function keyLengthFor(spec: KemSpec | SignerSpec, use: KeyUse): number {
  return use === 'public' ? spec.publicKeyLength : spec.secretKeyLength;
}

/** Valida algoritmo, uso y longitud de una key antes de operar con ella. */
export function requireKey<K extends 'kem' | 'signer'>(
  key: PqcKey,
  kind: K,
  use: KeyUse,
  operation: string,
): K extends 'kem' ? KemSpec : SignerSpec {
  const spec = getAlgorithm(key.algorithm);
  if (spec.kind !== kind) {
    throw new PqcError(
      'WRONG_ALGORITHM',
      `${operation} requiere una key ${kind === 'kem' ? 'ML-KEM' : 'ML-DSA'}, recibió ${key.algorithm}`,
    );
  }
  if (key.use !== use) {
    throw new PqcError('WRONG_KEY_USE', `${operation} requiere la key ${use}, recibió ${key.use}`);
  }
  if (key.bytes.length !== keyLengthFor(spec, use)) {
    throw new PqcError(
      'INVALID_KEY',
      `Key ${key.algorithm} ${use} con longitud inválida: ${key.bytes.length}`,
    );
  }
  return spec as K extends 'kem' ? KemSpec : SignerSpec;
}
