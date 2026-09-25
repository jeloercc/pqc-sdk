---
'@pqc-sdk/core': minor
---

FIPS 203/204 corrective pass 2.

New public API:

- `collectDecryptStream(secretKey, ciphertext)` — buffering wrapper around `decryptStream` that resolves to the full plaintext only after the whole stream authenticates; a tampered or truncated stream throws `PqcError` and never returns partial plaintext. It holds the whole plaintext in memory, so keep using `decryptStream` for payloads too large to buffer.
- `FIPS_ALGORITHMS` / `FipsAlgorithm` — the NIST-standardized subset of `SUPPORTED_ALGORITHMS` (`ml-kem-768`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`). `x-wing` is a CFRG draft construction and is deliberately excluded (FIPS 203 §3.3, matrix row F203-03).

Behavior changes:

- An RBG failure during ML-DSA key generation or `sign()` now throws `PqcError('RBG_FAILURE')` instead of a raw host error (F204-06, F204-07), matching the existing ML-KEM behavior (F203-11). `sign()` draws the 32-byte hedged-signing `rnd` through the same RBG boundary as encapsulation and zeroes it after use; signing remains hedged.
- `pqc.keys.generate({ algorithm: 'ml-dsa-44' })` logs a one-time `console.warn` noting that ML-DSA-44 is security category 2 and that ML-DSA-65 is the recommended default.

Tests: direct negative tests for the FIPS 203 §7.2 modulus check (F203-05) and the §7.3 `H(ek)` hash check (F203-10), FIPS 202 SHAKE known-answer tripwires (F204-21), hedged-signing freshness (F204-05), and an upgrade guard for the `@noble/post-quantum/hybrid.js` internals used by X-Wing. No serialized layout changed.
