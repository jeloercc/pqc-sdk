import { requireKey, SIGNATURE_ALGORITHMS, type SignerSpec } from './algorithms.js';
import { PqcError } from './errors.js';
import type {
  PqcKey,
  PublicKey,
  SecretKey,
  SignatureAlgorithm,
  SignatureOptions,
} from './types.js';
import { RbgFailureError, sampleRandomness } from './vendor/ml-kem/ml-kem.js';

/** FIPS 204 §5.2 caps the signing context string at 255 bytes. */
const MAX_CONTEXT_LENGTH = 255;

/** FIPS 204 Algorithm 2 step 5: rnd ← B^32 for hedged signing. */
const SIGNING_RND_LENGTH = 32;

const utf8 = new TextEncoder();

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? utf8.encode(data) : data;
}

function toNobleOptions(options?: SignatureOptions): { context: Uint8Array } | undefined {
  if (!options?.context) {
    return undefined;
  }
  if (options.context.length > MAX_CONTEXT_LENGTH) {
    throw new PqcError(
      'INVALID_CONTEXT',
      `Signature context must be at most ${MAX_CONTEXT_LENGTH} bytes, got ${options.context.length}`,
    );
  }
  return { context: options.context };
}

/**
 * Detects the one condition FIPS 204 §3.6.2 singles out for `verify`: a public key
 * whose length differs from the parameter set's.
 *
 * > "If an implementation of ML-DSA can accept inputs for σ or pk of any other length,
 * > it shall return false whenever the lengths of either of these inputs differ from
 * > their lengths specified in this standard."
 *
 * The signature half of that sentence is already satisfied — `@noble` returns `false`
 * for a wrong-length σ, and `verify`'s catch normalizes a throw to `false` besides. The
 * public-key half was not: `requireKey` throws `INVALID_KEY` on a length mismatch, and
 * it runs before the try block, so the rejection never reached the catch.
 *
 * This check is deliberately narrow and lives here rather than in `requireKey`.
 * Throwing `INVALID_KEY` for a malformed key is the right convention everywhere else in
 * the SDK — `encrypt`, `decrypt`, `sign`, the streaming entry points — because there a
 * bad key is an operator error with no meaningful "no" to return. `verify` is the one
 * operation whose contract is a boolean, and the one the standard names.
 *
 * Only the length is treated this way. An unknown algorithm, a KEM key, or a secret key
 * passed as public still throws through `requireKey` unchanged: none of those is a
 * length mismatch, and §3.6.2 does not speak to them.
 *
 * @returns `true` only when the key is a well-formed ML-DSA public key reference whose
 * byte length is wrong — the case that must verify to `false` instead of throwing.
 */
function hasWrongVerificationKeyLength(publicKey: PqcKey): boolean {
  // Widened on purpose: `publicKey.algorithm` is typed, but a hand-built or deserialized
  // object can carry anything at runtime, and an unknown algorithm is requireKey's to
  // report — not a length mismatch to swallow.
  const spec = (SIGNATURE_ALGORITHMS as Record<string, SignerSpec | undefined>)[
    publicKey.algorithm
  ];
  if (spec === undefined || publicKey.use !== 'public') {
    return false;
  }
  return publicKey.bytes.length !== spec.publicKeyLength;
}

/**
 * Signs data with ML-DSA (FIPS 204) in hedged mode (randomized signing, the
 * standard's default). Returns the signature, whose length depends on the
 * key's parameter set (2420 bytes for ML-DSA-44, 3309 for ML-DSA-65, 4627 for
 * ML-DSA-87).
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign(document, pair.secretKey);
 * ```
 */
export async function sign<A extends SignatureAlgorithm>(
  data: Uint8Array | string,
  secretKey: SecretKey<A>,
  options?: SignatureOptions,
): Promise<Uint8Array> {
  const spec = requireKey(secretKey, 'signer', 'secret', 'sign');
  const nobleOptions = toNobleOptions(options);
  // F204-07 (consistency with F203-11): FIPS 204 §5.2 Alg.2 step 7 requires an error
  // indication when rnd cannot be drawn. The vendored signer would call randomBytes
  // itself and leak whatever the host threw, so the SDK draws rnd here through the same
  // RBG boundary as ML-KEM encapsulation and key generation (`sampleRandomness`), which
  // maps every failure mode — throw, missing API, short buffer — to RbgFailureError.
  // Classifying the upstream error by its message instead would miss hosts whose
  // wording differs. Signing stays hedged: rnd is fresh per call and never
  // caller-supplied (F204-14/F204-15 unchanged).
  let rnd: Uint8Array;
  try {
    rnd = sampleRandomness(SIGNING_RND_LENGTH);
  } catch (cause) {
    if (cause instanceof RbgFailureError) {
      throw new PqcError(
        'RBG_FAILURE',
        `${secretKey.algorithm} signing aborted: the platform RBG failed to produce randomness`,
      );
    }
    throw cause;
  }
  try {
    return Promise.resolve(
      spec.signer.sign(toBytes(data), secretKey.bytes, { ...nobleOptions, extraEntropy: rnd }),
    );
  } finally {
    // The vendored signer only wipes entropy it generated itself (F204-09).
    rnd.fill(0);
  }
}

/**
 * Verifies an ML-DSA signature. Returns `false` for invalid or malformed
 * signatures, and — per FIPS 204 §3.6.2 — for a public key of the wrong length.
 * It never throws because of a corrupted signature or a mis-sized key; it throws
 * only when the key is not an ML-DSA public key at all (wrong algorithm, wrong
 * use, unknown algorithm) or when the context string exceeds 255 bytes.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 *
 * const valid = await pqc.verify(document, signature, pair.publicKey);
 * if (!valid) throw new Error('invalid signature');
 * ```
 */
export async function verify<A extends SignatureAlgorithm>(
  data: Uint8Array | string,
  signature: Uint8Array,
  publicKey: PublicKey<A>,
  options?: SignatureOptions,
): Promise<boolean> {
  // FIPS 204 §3.6.2: a wrong-length public key must verify to `false`, not throw.
  // Checked before requireKey, which would otherwise throw INVALID_KEY for it.
  if (hasWrongVerificationKeyLength(publicKey)) {
    return false;
  }
  const spec = requireKey(publicKey, 'signer', 'public', 'verify');
  // Validate the context outside the try so an oversized context throws
  // INVALID_CONTEXT (as sign does) instead of being swallowed as `false`.
  const nobleOptions = toNobleOptions(options);
  try {
    return Promise.resolve(
      spec.signer.verify(signature, toBytes(data), publicKey.bytes, nobleOptions),
    );
  } catch {
    return false;
  }
}
