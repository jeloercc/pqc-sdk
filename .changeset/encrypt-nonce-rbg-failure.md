---
'@pqc-sdk/core': patch
---

`pqc.encrypt` now reports a platform RNG failure while drawing its 12-byte AES-GCM nonce as `PqcError` with code `RBG_FAILURE`, like key generation, encapsulation and signing already did. Previously the host's raw error escaped from that step. Ciphertext bytes and the envelope format are unchanged.
