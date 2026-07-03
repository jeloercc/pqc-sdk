---
'@pqc-sdk/core': patch
---

Add performance benchmarks for the five core operations (ML-KEM-768 keygen/encrypt/decrypt, ML-DSA-65 keygen/sign/verify) with automatic regression detection in CI: every PR reports the measured numbers and fails when any operation exceeds 2.5x the committed baseline. `generateKeyPairFromSeed` now returns the narrow `KeyPair<A>` type inferred from its algorithm argument (type-level only, no runtime change).
