---
'@pqc-sdk/core': patch
---

Bump the pinned `@noble/post-quantum` from 0.6.1 to 0.7.1.

0.6.1 is outside upstream's support window (their `SECURITY.md` supports
`>=0.7.1`), so it no longer receives security fixes. 0.7.1 adds input
validation, broader zeroization of internal buffers, and detaches
caller-owned buffers on the hybrid key paths.

No output or format change. 0.7.0 removed the legacy `XWing` alias, so the
`x-wing` spec entry now imports `ml_kem768_x25519` — the same construction
under its current name. The X-Wing combiner and seed expansion are
byte-identical, and the ML-KEM `BaseCaseMultiply` change is an equivalent
reduction ordering, not a corrected result. Verified by the NIST ACVP
vectors, the X-Wing draft-10 Appendix C vectors, and the golden vectors,
which decrypt pre-existing 0.6.1-era ciphertexts unchanged.
