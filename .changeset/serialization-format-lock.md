---
'@pqc-sdk/core': patch
---

Lock the serialization formats across versions: normative spec in `docs/serialization-format.md` (key token layout, hybrid ciphertext byte layout, signature encoding, CLI key files, error contract, forward-compatibility rules) plus golden-vector tests generated with the published 0.3.8 — serialized keys for both algorithms and uses, a complete ciphertext, and a signature that every future version must keep deserializing and using correctly. Unknown version markers (`pqcv2` tokens, unknown ciphertext version byte) are pinned to fail closed with clear `PqcError` codes.
