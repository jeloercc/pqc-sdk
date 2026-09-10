---
'@pqc-sdk/core': minor
---

Repoint X-Wing's embedded ML-KEM-768 at the vendored, FIPS-corrected primitive

`pqc.keys.generate()`'s default algorithm, `x-wing`, embeds ML-KEM-768. Until now that
component still resolved to `@noble/post-quantum`'s own internal, unpatched `ml-kem.ts`,
not to the vendored copy at `packages/core/src/vendor/ml-kem/ml-kem.ts` that closed
**F203-19** (floating-point `Compress_d`) and **F203-18** (branch-based implicit-reject
selection) for the standalone `ml-kem-768` algorithm entry. Both rows had already closed
for that entry — this was a gap in what the closures covered, not a defect in either
correction. See `docs/compliance/FIPS-203-MATRIX.md` §3.10 for the full timeline: the gap
existed from each row's original closure (2026-09-07 and 2026-09-08) through 2026-09-09,
when it was found and closed in this pass.

`packages/core/src/x-wing.ts` now reconstructs `@noble/post-quantum/hybrid.js`'s own
`ml_kem768_x25519` preset verbatim — same argument order, same hard-coded
domain-separation label — substituting the vendored `ml_kem768` for the npm-internal one.
The preset's combiner (`combineKEMS`, `expandSeedXof`, `_ecdhKem`) is still imported from
`@noble/post-quantum/hybrid.js` rather than vendored: none of those three perform ML-KEM
arithmetic, so neither finding applies to them.

**Not a breaking change, and not a FIPS 203 coverage claim for X-Wing.** X-Wing is a CFRG
Internet-Draft construction (`draft-connolly-cfrg-xwing-kem-10`), not a FIPS 203
algorithm, and this fix does not change that — see `FIPS-203-MATRIX.md` §3.2. It was made
because a downstream consumer's shared secret does not carry a label recording which
named algorithm produced it: the arithmetic-method corrections that closed F203-19 and
F203-18 for `ml-kem-768` are equally worth having on the code path
`pqc.keys.generate()` actually uses by default.

**Interoperability.** Both corrections were proven output-identical to the code they
replaced across their full input domains when originally closed (`compress-equivalence.test.ts`,
`implicit-reject.test.ts`), so no key, ciphertext or shared-secret byte changes for any
given input. That argument is re-verified for the composite directly: `x-wing.test.ts`
cross-checks the vendored-backed and npm-backed presets bidirectionally — vendored
encapsulation decapsulates correctly under the npm preset and vice versa, deterministic
seeds produce byte-identical keys/ciphertext/shared-secret under both, and a tampered
ciphertext implicitly rejects to the same secret under both. Existing X-Wing keys and
ciphertexts remain valid.

`vendor/ml-kem/NOTICE.md` and `docs/compliance/FIPS-203-MATRIX.md` (§1.3, §3.2, §3.8,
§3.9, §3.10, §4.4) updated to describe the new boundary: X-Wing's embedded ML-KEM-768 is
now vendored; its X25519 component and its generic hybrid combiner remain Provider-scope,
since neither carries an ML-KEM finding.
