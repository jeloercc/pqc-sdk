/** Key encapsulation algorithm (hybrid encryption). */
export type KemAlgorithm = 'ml-kem-768';

/** Digital signature algorithm. */
export type SignatureAlgorithm = 'ml-dsa-65';

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
