---
'@pqc-sdk/core': minor
---

Expose ML-DSA-44 and ML-DSA-87, closing the last PARTIALLY CONFORMING row in FIPS-204-MATRIX.md

`pqc.keys.generate`, `pqc.sign` and `pqc.verify` now accept `'ml-dsa-44'` and `'ml-dsa-87'`
alongside the existing `'ml-dsa-65'`. `SignatureAlgorithm` widens from the closed
single-member union `'ml-dsa-65'` to `'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87'`, and
`SUPPORTED_ALGORITHMS` gains both new entries.

**Not a breaking change.** `SignerSpec.signer` moves from the concrete type `typeof
ml_dsa65` to a new structural interface, `NobleSigner` (mirroring `NobleKem` on the KEM
side) — this type is internal, never re-exported from `@pqc-sdk/core`'s public entry
point. `sign`/`verify` widen from a literal `'ml-dsa-65'` parameter type to generic-over-
`SignatureAlgorithm`, a supertype relaxation: every call that type-checked before still
type-checks identically. The one real consequence, flagged rather than glossed over: a
consumer with an exhaustive `switch` over `SignatureAlgorithm` gains two unhandled cases —
the same reasoning that made `RBG_FAILURE`'s addition to `PqcErrorCode` a `minor` rather
than a `patch`.

Both parameter sets resolve to the vendored, FIPS-corrected `ml-dsa.ts`
(`packages/core/src/vendor/ml-dsa/`), not to the npm package. Both FIPS 204 corrections
already closed for `ml-dsa-65` — F204-13 (integer-only `Decompose`/`Power2Round`) and
F204-10 (zeroization in `internal.verify`) — apply identically to `ml-dsa-44` and
`ml-dsa-87`, verified by reading the source rather than inferred from the fact that all
three share a package: they're built from three independent calls to the same
`getDilithium(opts)` factory, and both corrections are defined once inside that factory's
body, not reimplemented per parameter set.

**ACVP round-trip evidence per set, not follow-up work.** Six new NIST ACVP-Server vector
files (`mldsa44-{keygen,sigver}.json`, `mldsa87-{keygen,sigver}.json`) — same provenance as
the existing `mldsa65-*.json` pair — are wired into `nist-vectors.test.ts`. 20/16/20
keyGen+sigVer cases pass for ML-DSA-44/65/87 respectively.

**Consequence for the compliance matrix.** F204-01 (`docs/compliance/FIPS-204-MATRIX.md`
§3.1) closes from `PARTIALLY CONFORMING` to `CONFORMING`. F204-04 (ML-DSA-44's RBG
security-strength threshold) activates as a direct consequence and is determined
`INDETERMINATE` — the same reasoning as F204-02/F204-03: this assessment has no
visibility into the host RBG's approved security strength. F204-03's applicability text is
also corrected, since its ML-DSA-87 clause is no longer "not registered"; its
determination (`INDETERMINATE`) does not change.

`docs/serialization-format.md`'s key-length table and the CLI's `keygen --algorithm` help
text are updated to match.
