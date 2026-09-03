import { randomBytes } from '@noble/post-quantum/utils.js';

import { getAlgorithm, keyLengthFor } from './algorithms.js';
import { fromBase64Url, toBase64Url } from './base64url.js';
import { PqcError, truncateForError } from './errors.js';
import type { Algorithm, KeyPair, KeyUse, PqcKey } from './types.js';

const SERIAL_PREFIX = 'pqcv1';

/** Options for {@link generate}. */
export interface GenerateOptions<A extends Algorithm = Algorithm> {
  /**
   * Algorithm of the pair. Default: `'x-wing'` (the X25519 + ML-KEM-768
   * hybrid KEM). Pass `'ml-kem-768'` for the pure post-quantum KEM, or
   * `'ml-dsa-65'` for signing.
   */
  readonly algorithm?: A;
}

/**
 * Generates a post-quantum key pair. With no options it generates an
 * **X-Wing** hybrid pair (X25519 + ML-KEM-768), ready for `pqc.encrypt`.
 *
 * The no-argument default is hybrid because a break in either component
 * still leaves the other standing — the same reasoning behind TLS 1.3's
 * `X25519MLKEM768`, Signal's PQXDH, and the BSI and ANSSI recommendations.
 * ML-KEM-768 is young, and a cryptanalytic result against it would leave a
 * pure-PQ ciphertext with nothing to fall back on.
 *
 * **`'ml-kem-768'` remains fully supported and is the right choice in two
 * cases**: when FIPS certification scope matters (X-Wing is not covered by
 * FIPS 203, so a compliance regime requiring a certified KEM needs the pure
 * one), and when size or speed dominate (32 bytes less per envelope, and
 * roughly 2–4× faster per operation — see `docs/MIGRATION-0.8.md`).
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const encryption = await pqc.keys.generate(); // x-wing hybrid
 * const pureMlKem = await pqc.keys.generate({ algorithm: 'ml-kem-768' });
 * const signing = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * ```
 */
export async function generate(): Promise<KeyPair<'x-wing'>>;
export async function generate<A extends Algorithm>(
  options: GenerateOptions<A> & { algorithm: A },
): Promise<KeyPair<A>>;
export async function generate(options?: GenerateOptions): Promise<KeyPair>;
export async function generate(options?: GenerateOptions): Promise<KeyPair> {
  const algorithm = options?.algorithm ?? 'x-wing';
  const spec = getAlgorithm(algorithm);
  return Promise.resolve(generateKeyPairFromSeed(algorithm, randomBytes(spec.seedLength)));
}

/**
 * Deterministic generation from a seed. Internal and test use (NIST vectors).
 * Prefer {@link generate} for normal use.
 */
export function generateKeyPairFromSeed<A extends Algorithm>(
  algorithm: A,
  seed: Uint8Array,
): KeyPair<A> {
  const spec = getAlgorithm(algorithm);
  if (seed.length !== spec.seedLength) {
    throw new PqcError(
      'INVALID_KEY',
      `${algorithm} seed must be ${spec.seedLength} bytes, got ${seed.length}`,
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
 * Serializes a key to a portable string: `pqcv1.<algorithm>.<use>.<base64url>`.
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
    throw new PqcError('INVALID_KEY', `${key.algorithm} ${key.use} key has invalid length`);
  }
  return `${SERIAL_PREFIX}.${key.algorithm}.${key.use}.${toBase64Url(key.bytes)}`;
}

/** Asserts the algorithm and use a caller expects from a deserialized key. */
export interface ExpectedKey<A extends Algorithm = Algorithm, U extends KeyUse = KeyUse> {
  readonly algorithm: A;
  readonly use: U;
}

/**
 * Rebuilds a key from the {@link serialize} format. Validates version,
 * algorithm, use and length; on any problem it throws {@link PqcError} with
 * code `INVALID_SERIALIZED_KEY` or `INVALID_KEY`.
 *
 * Pass `expected` to assert the algorithm and use, getting back a narrow key
 * type (e.g. `PublicKey<'ml-kem-768'>`) that drops straight into `encrypt` /
 * `sign` without an `as never` cast. A mismatch throws `WRONG_ALGORITHM` or
 * `WRONG_KEY_USE`.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const token = pqc.keys.serialize((await pqc.keys.generate()).publicKey);
 * // Narrow to a typed key by asserting the expected algorithm and use:
 * const publicKey = pqc.keys.deserialize(token, { algorithm: 'ml-kem-768', use: 'public' });
 * const ciphertext = await pqc.encrypt('payload', publicKey);
 * ```
 */
export function deserialize(serialized: string): PqcKey;
export function deserialize<A extends Algorithm, U extends KeyUse>(
  serialized: string,
  expected: ExpectedKey<A, U>,
): PqcKey<A, U>;
export function deserialize(serialized: string, expected?: ExpectedKey): PqcKey {
  const parts = serialized.split('.');
  if (parts.length !== 4 || parts[0] !== SERIAL_PREFIX) {
    throw new PqcError(
      'INVALID_SERIALIZED_KEY',
      'Expected format: pqcv1.<algorithm>.<use>.<base64url>',
    );
  }
  const [, algorithm, use, encoded] = parts as [string, string, string, string];
  const spec = getAlgorithm(algorithm);
  if (use !== 'public' && use !== 'secret') {
    // The segment comes from an untrusted serialized token: bound the echo.
    throw new PqcError('INVALID_SERIALIZED_KEY', `Unknown key use: ${truncateForError(use)}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(encoded);
  } catch (cause) {
    throw new PqcError(
      'INVALID_SERIALIZED_KEY',
      cause instanceof Error ? cause.message : 'Invalid base64url',
    );
  }
  const key: PqcKey = { algorithm: algorithm as Algorithm, use, bytes };
  if (bytes.length !== keyLengthFor(spec, key.use)) {
    throw new PqcError(
      'INVALID_KEY',
      `${algorithm} ${use} key must be ${keyLengthFor(spec, key.use)} bytes, got ${bytes.length}`,
    );
  }
  if (expected !== undefined) {
    if (key.algorithm !== expected.algorithm) {
      throw new PqcError(
        'WRONG_ALGORITHM',
        `Expected an ${expected.algorithm} key, got ${key.algorithm}`,
      );
    }
    if (key.use !== expected.use) {
      throw new PqcError('WRONG_KEY_USE', `Expected the ${expected.use} key, got ${key.use}`);
    }
  }
  return key;
}
