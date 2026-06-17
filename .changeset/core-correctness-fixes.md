---
'@pqc-sdk/core': minor
---

Core correctness fixes for ML-KEM hybrid encryption and base64url decoding.

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
