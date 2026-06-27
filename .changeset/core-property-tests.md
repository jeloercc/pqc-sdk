---
'@pqc-sdk/core': patch
---

Add property-based tests (fast-check) that assert the core crypto invariants
over many generated inputs, complementing the example-based suite:
`decrypt(encrypt(x))` round-trips for any payload; any single-byte tamper of a
ciphertext fails closed with a `PqcError` and never returns plaintext;
`deserialize(serialize(k))` preserves any key; a genuine signature verifies and
any single-byte tamper of the signature or message is rejected; and base64url
round-trips for any byte array. Runs are seeded for deterministic CI and bounded
so test time stays modest. Dev-dependency and tests only; no API or runtime
change.
