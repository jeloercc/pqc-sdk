---
'@pqc-sdk/cli': minor
---

Add `pqc encrypt` and `pqc decrypt` commands: file encryption for the holder of an ML-KEM-768 key pair, fully interoperable with envelopes produced by `@pqc-sdk/core`'s `encrypt()`. Both commands refuse to overwrite existing output files unless `--force` is passed.
