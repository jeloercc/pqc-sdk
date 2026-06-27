---
'@pqc-sdk/core': minor
---

Harden the core API and crypto surface:

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
