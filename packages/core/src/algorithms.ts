import { XWing } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { PqcError, truncateForError } from './errors.js';
import type { Algorithm, KemAlgorithm, KeyUse, PqcKey, SignatureAlgorithm } from './types.js';

interface AlgorithmSpec {
  readonly seedLength: number;
  readonly publicKeyLength: number;
  readonly secretKeyLength: number;
}

/**
 * Structural KEM surface shared by `@noble` implementations (`ml_kem768`,
 * `XWing`). The optional second argument of `encapsulate` is the
 * derandomization seed used only by deterministic test vectors.
 */
export interface NobleKem {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(
    publicKey: Uint8Array,
    seed?: Uint8Array,
  ): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

export interface KemSpec extends AlgorithmSpec {
  readonly kind: 'kem';
  /** Envelope format version byte this KEM produces (docs/serialization-format.md §2). */
  readonly envelopeVersion: number;
  readonly headerId: number;
  readonly ciphertextLength: number;
  readonly kem: NobleKem;
}

export interface SignerSpec extends AlgorithmSpec {
  readonly kind: 'signer';
  readonly signatureLength: number;
  readonly signer: typeof ml_dsa65;
}

export const KEM_ALGORITHMS: Record<KemAlgorithm, KemSpec> = {
  'ml-kem-768': {
    kind: 'kem',
    envelopeVersion: 1,
    headerId: 1,
    kem: ml_kem768,
    seedLength: 64,
    publicKeyLength: 1184,
    secretKeyLength: 2400,
    ciphertextLength: 1088,
  },
  // X-Wing (draft-connolly-cfrg-xwing-kem-10): X25519 + ML-KEM-768 hybrid.
  // The secret key is the 32-byte seed (draft §5.2); the public key is
  // pk_M(1184)‖pk_X(32) and the ciphertext ct_M(1088)‖ct_X(32) (draft §5.4),
  // both opaque spec-defined units. x-wing keys produce/open the pqcenc.v2
  // envelope (version byte 0x02, headerId 0x02 — docs/serialization-format.md §2.2).
  'x-wing': {
    kind: 'kem',
    envelopeVersion: 2,
    headerId: 2,
    kem: XWing,
    seedLength: 32,
    publicKeyLength: 1216,
    secretKeyLength: 32,
    ciphertextLength: 1120,
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
    // The name can come from an untrusted serialized key: bound the echo.
    throw new PqcError(
      'UNSUPPORTED_ALGORITHM',
      `Unsupported algorithm: ${truncateForError(algorithm)}`,
    );
  }
  return spec;
}

export function keyLengthFor(spec: KemSpec | SignerSpec, use: KeyUse): number {
  return use === 'public' ? spec.publicKeyLength : spec.secretKeyLength;
}

/** Validates a key's algorithm, use and length before operating with it. */
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
      `${operation} requires an ${kind === 'kem' ? 'ML-KEM' : 'ML-DSA'} key, got ${key.algorithm}`,
    );
  }
  if (key.use !== use) {
    throw new PqcError('WRONG_KEY_USE', `${operation} requires the ${use} key, got ${key.use}`);
  }
  if (key.bytes.length !== keyLengthFor(spec, use)) {
    throw new PqcError(
      'INVALID_KEY',
      `${key.algorithm} ${use} key has invalid length: ${key.bytes.length}`,
    );
  }
  return spec as K extends 'kem' ? KemSpec : SignerSpec;
}
