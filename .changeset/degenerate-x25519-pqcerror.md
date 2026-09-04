---
'@pqc-sdk/core': patch
---

`encrypt` and `encryptStream` now fail with `PqcError('INVALID_KEY')` when a
KEM public key is the right length but not a valid encapsulation key, instead
of letting a raw `@noble` error escape.

This is reachable with an X-Wing public key whose `pk_X` half is a small-order
X25519 point (`0`, `1`, either order-8 point, or `p-1`): `@noble/curves`
throws because those drive the shared secret to all-zero. The behaviour was
already fail-closed — nothing was decryptable and no plaintext leaked — but
the error crossed the API boundary unmapped, contrary to the documented
contract that failures surface as a `PqcError`. `decrypt` already mapped the
equivalent decapsulation case.

Also adds a public-key mutation matrix (`key-mutations.test.ts`), covering the
`pk_M` and `pk_X` regions of X-Wing keys, ML-KEM-768 encapsulation keys, and
degenerate `ct_X` on decapsulation — regions no suite previously tampered.
