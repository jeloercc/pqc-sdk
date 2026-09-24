/**
 * Key encapsulation algorithm (hybrid encryption). `x-wing` is the PQ/T
 * hybrid KEM (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem); its
 * envelope format (`pqcenc.v2`) lands separately — see
 * `docs/proposals/hybrid-envelope.md`.
 *
 * All three FIPS 203 ML-KEM parameter sets are supported:
 * - `ml-kem-512`  — security category 1 (≈ AES-128)
 * - `ml-kem-768`  — security category 3 (≈ AES-192, recommended default)
 * - `ml-kem-1024` — security category 5 (≈ AES-256)
 */
export type KemAlgorithm = 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024' | 'x-wing';

/** Digital signature algorithm. */
export type SignatureAlgorithm = 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';

/** Algorithms supported by the SDK. */
export type Algorithm = KemAlgorithm | SignatureAlgorithm;

/** Role of a key within its pair. */
export type KeyUse = 'public' | 'secret';

/** SDK key: raw bytes plus algorithm and use metadata. */
export interface PqcKey<A extends Algorithm = Algorithm, U extends KeyUse = KeyUse> {
  readonly algorithm: A;
  readonly use: U;
  readonly bytes: Uint8Array;
}

/** Public key, safe to share. */
export type PublicKey<A extends Algorithm = Algorithm> = PqcKey<A, 'public'>;

/** Secret key. Must never leave its owner's environment. */
export type SecretKey<A extends Algorithm = Algorithm> = PqcKey<A, 'secret'>;

/** Key pair produced by `pqc.keys.generate`. */
export interface KeyPair<A extends Algorithm = Algorithm> {
  readonly algorithm: A;
  readonly publicKey: PublicKey<A>;
  readonly secretKey: SecretKey<A>;
}

/** Signing/verification options (FIPS 204 §5.2, optional context string). */
export interface SignatureOptions {
  /** Context string of up to 255 bytes. Default: empty. */
  readonly context?: Uint8Array;
}
