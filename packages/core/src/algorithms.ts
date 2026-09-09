import { PqcError, truncateForError } from './errors.js';
// ML-KEM and ML-DSA resolve to vendored copies of @noble/post-quantum 0.7.1, not to the npm
// package. Four FIPS corrections live inside the primitives, and the published `dist`
// imports @noble/post-quantum as an external runtime import — consumers execute their own
// registry copy, so a patch or override here would never reach them. Vendoring into `src/`
// is the only mechanism by which those corrections ship.
//
//   ML-KEM  — F203-19 (floating-point Compress_d), F203-11 (RBG failure attribution),
//             F203-18 (branch-free implicit-reject selection).
//   ML-DSA  — F204-13 (floating-point Decompose/Power2Round), F204-10 (zeroization on the
//             verification path).
//
// X-Wing's embedded ML-KEM-768 gets the same two corrections via `./x-wing.ts`, which
// reconstructs @noble/post-quantum/hybrid.js's own `ml_kem768_x25519` preset with the
// vendored `ml_kem768` substituted for its npm-internal one — see that file for why the
// combiner itself (`combineKEMS`/`expandSeedXof`/`_ecdhKem`) did not need vendoring.
// SLH-DSA still resolves against the npm package (not yet implemented by this SDK). See
// packages/core/src/vendor/ml-kem/NOTICE.md for provenance and the re-vendoring procedure,
// and docs/compliance/FIPS-203-MATRIX.md §1.3 / FIPS-204-MATRIX.md §1.3 for why it matters.
import { ml_dsa65 } from './vendor/ml-dsa/ml-dsa.js';
import { ml_kem768, RbgFailureError } from './vendor/ml-kem/ml-kem.js';
import { ml_kem768_x25519 } from './x-wing.js';
import type { Algorithm, KemAlgorithm, KeyUse, PqcKey, SignatureAlgorithm } from './types.js';

interface AlgorithmSpec {
  readonly seedLength: number;
  readonly publicKeyLength: number;
  readonly secretKeyLength: number;
}

/**
 * Structural KEM surface shared by `@noble` implementations (`ml_kem768`,
 * `ml_kem768_x25519`). The optional second argument of `encapsulate` is the
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
    kem: ml_kem768_x25519,
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

/**
 * Encapsulates to a public key, mapping any upstream `@noble` throw to a
 * documented `PqcError`.
 *
 * Length validation happens in {@link requireKey}, but a key can be the right
 * length and still be cryptographically unusable: X-Wing's `pk_X` half is an
 * X25519 element, and `@noble/curves` throws for the small-order points
 * (`0`, `1`, both order-8 points, `p-1`) because they drive the shared secret
 * to all-zero. That is fail-closed and correct, but the raw error must not
 * reach callers — errors carry only lengths, algorithm names and key use.
 *
 * @example
 * ```ts
 * import { KEM_ALGORITHMS, encapsulateTo } from '@pqc-sdk/core';
 *
 * const spec = KEM_ALGORITHMS['x-wing'];
 * const { publicKey } = spec.kem.keygen();
 * const { cipherText, sharedSecret } = encapsulateTo(spec, publicKey, 'x-wing');
 * console.log(cipherText.length, sharedSecret.length); // 1120 32
 * ```
 */
export function encapsulateTo(
  spec: KemSpec,
  publicKey: Uint8Array,
  algorithm: KemAlgorithm,
): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  try {
    return spec.kem.encapsulate(publicKey);
  } catch (cause) {
    if (cause instanceof PqcError) {
      throw cause;
    }
    // Order matters: the specific case first. FIPS 203 Algorithm 20 (steps 2-4) separates
    // "the RBG failed" from an input-check failure, so the two must not collapse into one
    // code — an entropy outage would otherwise send an operator to debug key distribution.
    // Only reachable for ml-kem-768, which resolves to the vendored primitive; the x-wing
    // path still falls through to INVALID_KEY below.
    if (cause instanceof RbgFailureError) {
      throw new PqcError(
        'RBG_FAILURE',
        `${algorithm} encapsulation aborted: the platform RBG failed to produce randomness`,
      );
    }
    throw new PqcError('INVALID_KEY', `${algorithm} public key is not a valid encapsulation key`);
  }
}
