---
'@pqc-sdk/core': patch
---

Fixed three findings from an adversarial audit of the CIRCL interop work (the previous two patches):

- **The important one:** `interop-circl.test.ts` never called `sign()` or `encapsulate()` — a mutation test proved a garbage signer passed all 10 tests, since the suite only re-verified/re-decapsulated bytes committed at generation time. Added round-trip assertions that call `pqc.sign()`/`encapsulate()` fresh on every CI run, using the same key material CIRCL already cross-checked, and confirm the fresh output verifies/decapsulates correctly. Re-ran the same mutation afterward to confirm it now fails loudly (3 new tests go red) instead of passing silently. The test file's header states plainly what this does and doesn't prove — it's a self-consistency guard, not a repeated cross-implementation check (Go still never runs in CI).
- **Determinism:** `generate-circl-vectors.mts` used fresh random seeds for every keygen, sign, and encapsulate call, so two regenerations never matched — undermining the ability to diff a fresh run against the committed vectors. Fixed all of it: literal fixed seeds for keygen (ML-DSA/X-Wing/ML-KEM), `extraEntropy: false` for ML-DSA signing, explicit fixed encapsulation seeds on both the SDK and CIRCL side (the Go helper's request shape gained a `seedHex` field, replacing its own `crypto/rand` call). Verified by running the generator twice and diffing: byte-identical except `meta.generatedAt`.
- **Asymmetry:** documented, not "fixed" as literally requested — routing the generator's Direction A (SDK signs, CIRCL verifies) through the public `pqc.sign()` turned out to be incompatible with the determinism fix above, since `pqc.sign()` deliberately never exposes `extraEntropy` (F204-14). Direction A stays on the vendored primitive for reproducibility; the new round-trip test now exercises `pqc.sign()` live on every CI run instead, which covers the same underlying concern (the real public entry point actually getting exercised).

Test + generator + docs only — no `packages/*` runtime behavior changed.
