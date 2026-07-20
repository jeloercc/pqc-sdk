---
'@pqc-sdk/core': minor
---

New `x-wing` KEM algorithm (X25519 + ML-KEM-768 hybrid per draft-connolly-cfrg-xwing-kem-10): `pqc.keys.generate({ algorithm: 'x-wing' })` generates a pair (1216-byte public key, 32-byte seed secret key) that serializes with the existing `pqcv1` token format, validated against the draft's Appendix C test vectors. The hybrid envelope format (`pqcenc.v2`) is not implemented yet — `encrypt`/`decrypt` fail closed with `UNSUPPORTED_ALGORITHM` on x-wing keys until it lands. The no-argument `keys.generate()` default is unchanged (`ml-kem-768`).
