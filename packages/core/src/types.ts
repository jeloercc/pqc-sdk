/** Algoritmo de encapsulamiento de claves (cifrado híbrido). */
export type KemAlgorithm = 'ml-kem-768';

/** Algoritmo de firma digital. */
export type SignatureAlgorithm = 'ml-dsa-65';

/** Algoritmos soportados por el SDK. */
export type Algorithm = KemAlgorithm | SignatureAlgorithm;

/** Rol de una key dentro de su par. */
export type KeyUse = 'public' | 'secret';

/** Key del SDK: bytes crudos más metadata de algoritmo y uso. */
export interface PqcKey<A extends Algorithm = Algorithm, U extends KeyUse = KeyUse> {
  readonly algorithm: A;
  readonly use: U;
  readonly bytes: Uint8Array;
}

/** Key pública, segura de compartir. */
export type PublicKey<A extends Algorithm = Algorithm> = PqcKey<A, 'public'>;

/** Key secreta. Nunca debe salir del entorno del dueño. */
export type SecretKey<A extends Algorithm = Algorithm> = PqcKey<A, 'secret'>;

/** Par de keys generado por `pqc.keys.generate`. */
export interface KeyPair<A extends Algorithm = Algorithm> {
  readonly algorithm: A;
  readonly publicKey: PublicKey<A>;
  readonly secretKey: SecretKey<A>;
}

/** Opciones de firma/verificación (FIPS 204 §5.2, context string opcional). */
export interface SignatureOptions {
  /** Context string de hasta 255 bytes. Default: vacío. */
  readonly context?: Uint8Array;
}
