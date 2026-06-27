# @pqc-sdk/core

## 0.3.1

### Patch Changes

- 6fcd7a4: Stabilize the multi-megabyte encrypt/decrypt round-trip test against CI flakes.
  It ran on the default 5s timeout, which is too tight when `turbo run test`
  executes the core and CLI suites concurrently and v8 coverage instrumentation
  slows the 3 MB operation under CPU contention. Give it a generous explicit
  timeout so it cannot flake. Test-only; no API or runtime change.
- 6fcd7a4: Add property-based tests (fast-check) that assert the core crypto invariants
  over many generated inputs, complementing the example-based suite:
  `decrypt(encrypt(x))` round-trips for any payload; any single-byte tamper of a
  ciphertext fails closed with a `PqcError` and never returns plaintext;
  `deserialize(serialize(k))` preserves any key; a genuine signature verifies and
  any single-byte tamper of the signature or message is rejected; and base64url
  round-trips for any byte array. Runs are seeded for deterministic CI and bounded
  so test time stays modest. Dev-dependency and tests only; no API or runtime
  change.
- 6fcd7a4: Close the last open edge-case coverage gap from the June 2026 audit (finding
  I1): the `verify` defense-in-depth catch path is now exercised by a focused
  regression test. It proves `verify` fails closed to `false` if the underlying
  signer ever throws — no signature byte-pattern makes `@noble`'s verify throw in
  practice (it returns `false` for every malformed signature), so the signer is
  stubbed to throw to genuinely cover the branch. Test-only; no API or runtime
  behavior change.

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
