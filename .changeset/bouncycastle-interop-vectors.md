---
'@pqc-sdk/core': patch
---

Added BouncyCastle (Java) as a second, independent interop counterpart for ML-KEM-768 and ML-DSA-44/65/87, alongside CIRCL (Go) — Phase 3 of the interop plan. No X-Wing: BouncyCastle does not implement it.

Uses `org.bouncycastle:bcprov-jdk18on:1.86`'s non-deprecated FIPS-named API (`org.bouncycastle.crypto.{signers,kems}` / `org.bouncycastle.crypto.params`), confirmed by reading the actual jar and source before writing anything — not the deprecated `org.bouncycastle.pqc.crypto.{mlkem,mldsa}` classes of the same name, and never the legacy round-3 "Dilithium"/"Kyber" classes (a different algorithm, also present in the jar).

Same discipline as the CIRCL work, applied from the start rather than fixed afterward:

- **Deterministic, verified by diff.** Fixed seeds for every keygen; `{ extraEntropy: false }` on the SDK's ML-DSA signing (confirmed BC's `MLDSASigner` supports the equivalent — omitting the `SecureRandom` leaves FIPS 204's `rnd` zeroed, read directly from `MLDSASigner.java` before relying on it); explicit fixed seeds for ML-KEM encapsulation on both sides (BC's `MLKEMGenerator.internalGenerateEncapsulated` takes the randomness as an explicit parameter). Verified by regenerating twice and diffing: byte-identical except `meta.generatedAt`.
- **Same `meta` provenance shape** as the CIRCL vectors: `counterpartVersion` read from the jar's own manifest at generation time (not hand-typed), `regenerateCommand`, `generatedAt`, `note`.
- **Java stays out of CI.** `packages/core/scripts/interop/generate-bc-vectors.mts` (+ a small `BCHelper.java` CLI, plain-args rather than JSON-over-stdin since the JDK has no bundled JSON library) is human-run; `packages/core/src/interop-bc.test.ts` only verifies the committed vectors against this SDK's own code.
- **Both directions**, matching the CIRCL work: SDK signs → BC verifies, BC signs → `pqc.verify` accepts; SDK encapsulates → BC decapsulates, BC encapsulates → SDK decapsulates.
- **Round-trip tests from day one** (the gap the CIRCL audit found and had to retrofit): `pqc.sign()`/`encapsulate()` are exercised fresh on every CI run against BC-cross-checked key material. Verified by the same mutation test that exposed the original gap — forced the vendored ML-DSA `sign()` to return garbage, confirmed the new round-trip tests fail, reverted.

All cross-checks passed against BouncyCastle on the first real run — no mismatch to report.

Test + generator + docs only — no `packages/*` runtime behavior changed.
