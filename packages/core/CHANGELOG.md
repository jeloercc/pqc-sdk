# @pqc-sdk/core

## 0.3.0

### Minor Changes

- 499b31f: Harden the core API and crypto surface:

  - `deserialize(token, { algorithm, use })` is a new typed overload that returns a
    narrow key type (e.g. `PublicKey<'ml-kem-768'>`), so deserialized keys drop
    straight into `encrypt`/`sign` without an `as never` cast. A mismatch throws
    `WRONG_ALGORITHM` or `WRONG_KEY_USE`. The `ExpectedKey` type is now exported.
  - Signature `context` longer than the FIPS 204 limit of 255 bytes now throws a
    `PqcError('INVALID_CONTEXT')` consistently from both `sign` and `verify`
    (previously `sign` leaked a raw error and `verify` silently returned `false`).
  - `decapsulate` now runs inside `decrypt`'s try/catch, so any unexpected throw is
    normalized to the documented `DECRYPTION_FAILED` instead of leaking upstream.
  - The `@noble/post-quantum` and `@noble/ciphers` cryptographic dependencies are
    pinned to exact versions so a downstream install gets the build that passed the
    NIST vectors.

## 0.2.0

### Minor Changes

- 156cfee: Core correctness fixes for ML-KEM hybrid encryption and base64url decoding.

  - **Fix package description**: drop `SLH-DSA` from the package description, since
    only ML-KEM-768 and ML-DSA-65 are implemented (`SUPPORTED_ALGORITHMS`).
  - **Authenticate the ciphertext header**: the 2-byte header (`FORMAT_VERSION`,
    `headerId`) is now bound as AES-GCM additional authenticated data on both
    encrypt and decrypt, so it is covered by the GCM tag.

    > **Breaking change to the ciphertext format.** This changes the authenticated
    > wire format: ciphertexts produced by `0.1.2` are **not** decryptable by this
    > release, and ciphertexts produced by this release are not decryptable by
    > `0.1.2`. Re-encrypt any data that must remain readable across the upgrade.

  - **Reject non-canonical base64url**: `fromBase64Url` now throws a `TypeError`
    when the trailing bits of the final group are non-zero, instead of silently
    decoding non-canonical input.

## 0.1.2

### Patch Changes

- 82bbac3: Translate all user-facing text to English: CLI command and flag descriptions,
  CLI output (success messages, warnings, audit report, errors), files generated
  by `pqc init`, every typed error message in core, the full public API JSDoc
  (including examples, which feed the generated API reference), package
  descriptions, and both READMEs. Error `code` values are unchanged, so programs
  handling `PqcError` by code are unaffected.

## 0.1.1

### Patch Changes

- c2dbf93: Fix: el export `version` ahora se inyecta en build time desde el `package.json`
  del paquete, en vez de estar hardcodeado. Los bumps de changesets se reflejan
  solos en ESM, CJS y los types.

## 0.1.0

### Minor Changes

- aac9044: Primera release pública: API de cifrado híbrido ML-KEM-768 + AES-256-GCM,
  firmas ML-DSA-65 con context strings, serialización de keys a base64url, y CLI
  con `init`, `keygen` y `audit`.
