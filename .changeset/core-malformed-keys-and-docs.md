---
'@pqc-sdk/core': patch
---

Malformed key arguments now fail with a documented `PqcError` instead of a raw
`TypeError`.

- `encrypt`, `decrypt`, `encryptStream`, `decryptStream` /
  `collectDecryptStream`, `sign`, `verify` and `keys.serialize` check that the
  key is an object with a string `algorithm`, a string `use` and `Uint8Array`
  `bytes`, and throw `PqcError('INVALID_KEY')` otherwise (for example when a
  JavaScript caller passes `undefined` or swaps the key and data arguments).
  `bytes` is checked the way `@noble/hashes` does (`isBytes`), so a
  `Uint8Array` from another realm (`node:vm`, iframes, Jest with jsdom) is
  still accepted, as it was in 0.11.0.
- **Behavior change in `verify`:** a malformed public key now always
  throws `PqcError('INVALID_KEY')`. Before, depending on
  the shape, `verify` either returned `false` (for example `bytes` given as a
  plain array) or threw a raw `TypeError` (for example `undefined`). A
  correctly shaped ML-DSA public key of the wrong length still returns
  `false`, as FIPS 204 requires.
- An algorithm name that is not a string (e.g. `generate({ algorithm: 42 })`)
  now reports `UNSUPPORTED_ALGORITHM` instead of throwing a `TypeError` while
  building the error message.

Documentation:

- `StreamOptions.chunkSize` JSDoc states the real range, 2^0 (1 byte) to
  2^24 (16 MiB), matching the code and `docs/serialization-format.md` §9.2.
- The package README names X-Wing as the default hybrid KEM, says the SDK is
  tested against NIST ACVP known-answer vectors and is not FIPS 140-3 / CMVP
  validated, and describes ML-KEM/ML-DSA as `@noble/post-quantum` 0.7.1
  vendored with documented FIPS 203/204 corrections, with partial (not
  absent) memory zeroization.
