---
'@pqc-sdk/core': minor
---

Vendor the ML-DSA primitive and close two FIPS 204 findings

`ml-dsa-65` now resolves to a vendored copy of `@noble/post-quantum@0.7.1` at
`packages/core/src/vendor/ml-dsa/ml-dsa.ts` rather than to the npm package. X-Wing and
SLH-DSA continue to resolve against the npm package; ML-KEM was already vendored.

This was necessary for the same reason as the ML-KEM vendoring: the published `dist`
imports `@noble/post-quantum` as an external runtime import, so consumers execute their own
registry-resolved copy and no patch or override in this repository could ever have reached
them. Two corrections now ship:

- **F204-13** — `Decompose`, `Power2Round`, `HINT_M` and the two `GAMMA2` constants used
  `Math.floor(x / y)`. In JavaScript `/` is always IEEE-754 double division, and wrapping it
  in `Math.floor` does not change the arithmetic performed, so all five were floating-point
  operations — which FIPS 204 §3.6.4 prohibits outright. They are now BigInt exact division
  where the divisor is not a power of two, and a bit shift where it is, following §3.6.4's
  own guidance. Verified exhaustively over the complete domain: both functions reduce their
  input `mod q` first, so this is all of Z_q — 8,285,185 + 8,118,529 evaluations for
  `Decompose` across both γ₂ values and 8,380,417 for `Power2Round`, with **0
  discrepancies** against the originals.
- **F204-10** — `internal.verify` contained no `cleanBytes` call at all; every one of the 14
  in the file was in key generation or signing. FIPS 204 §3.6.3 extends the destruction duty
  explicitly to verification, citing signatures used as bearer tokens and signatures over
  confidential plaintext. Verification now zeroizes its intermediates (`t1`, `tr`, `mu`,
  `z`, `h`, `c`, `zNtt`, `c2`, `wTick1`) in a `finally`, so it happens on all seven early
  `return false` paths and not only on success.

**Not a breaking change.** No key, signature or envelope format changed, and no consumer
code needs to change. Both corrections alter _method_, not output — §3.6.4 is a prohibition
on the arithmetic medium, and the original expressions were already bit-exact. That was
cross-verified directly against the unpatched npm primitive rather than assumed:

| Direction                                     | Result |
| --------------------------------------------- | ------ |
| vendored `pqc.sign` → npm `ml_dsa65.verify`   | `true` |
| npm `ml_dsa65.sign` → vendored `pqc.verify`   | `true` |
| npm `keygen` + `sign` → vendored `pqc.verify` | `true` |

Existing signatures and keys remain valid in both directions. The 31 NIST ACVP vectors pass
unchanged through the public API.

Two things worth knowing for maintenance:

- The vendored `ml-dsa.ts` reuses `_crystals.ts` and `utils.ts` from `vendor/ml-kem/` rather
  than duplicating them. Nothing in those shared files was modified to accommodate ML-DSA.
- BigInt division in `Decompose` measured ≈4.2× the cost of the float expression in
  isolation, and `Decompose` runs per coefficient during both signing and verification.
  `Power2Round` uses a shift and is unaffected. This is the same trade-off already accepted
  for ML-KEM's `Compress_d`, and it is a known cost of conformance rather than an oversight.

On any future `@noble/post-quantum` bump, re-vendor and re-apply the marked modifications
rather than hand-merging — see `packages/core/src/vendor/ml-kem/NOTICE.md`. The equivalence
and zeroization suites are the intended tripwire.

See `docs/compliance/FIPS-204-MATRIX.md` §3.5 and §3.6 for the full evidence.
