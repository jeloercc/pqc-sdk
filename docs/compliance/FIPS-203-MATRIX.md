# FIPS 203 (ML-KEM) — Conformance Matrix

**Object of assessment:** `@pqc-sdk/core` @ `0.8.3`, commit `3d76be9`, branch `main`
**Normative document:** FIPS 203, _Module-Lattice-Based Key-Encapsulation Mechanism
Standard_ (NIST, August 2024)
**Primitive provider:** `@noble/post-quantum@0.7.1` (exact pin), with the ML-KEM surface
vendored into `packages/core/src/vendor/ml-kem/` — see §1.3
**Assessment date:** 2026-09-07 (initial), 2026-09-07 (corrective pass), 2026-09-09
(corrective pass — see §4.4)
**Method:** static source analysis. Rows recorded as CONFORMING on the strength of a
correction cite the specific test that demonstrates it; those tests were executed.

---

## 1. Scope and reading instructions

This matrix records, requirement by requirement, the state of FIPS 203 conformance
for the ML-KEM surface of `packages/core`.

It began as a pure findings document, per the project's findings-before-fixes rule: the
assessment pass changed nothing. Remediation then landed separately, referencing the
`F203-nn` identifiers, and this document now also records which findings were closed, by
what change, and on what evidence. A row moves to CONFORMING only when a named,
executed test demonstrates it — never on the strength of a code change alone, and never
because a fix became _possible_ (see §3.8 for a row deliberately left open on exactly
that ground).

### 1.1 Keyword semantics

FIPS 203 §2.1 (Terms and Definitions) defines exactly two normative keywords:

> `shall` — Used to indicate a requirement of this standard.
> `should` — Used to indicate a strong recommendation but not a requirement of this
> standard.

The word **`must` is not defined by FIPS 203**, yet it appears in the body text (for
example, §3.3: "A fresh string of random bytes must be generated for every such
invocation"). Statements resting solely on an undefined `must` are recorded here with
their normative force marked `MUST (undefined)` and are **not** treated as discharged
or as breached; their interpretation remains open.

### 1.2 Status vocabulary

| Status                     | Meaning                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **CONFORMING**             | Requirement is applicable, satisfied, and supported by objective evidence in this repository.                                   |
| **CONFORMING (delegated)** | Requirement is satisfied by the pinned provider, verified by source inspection, but not guarded by any test in this repository. |
| **PARTIALLY CONFORMING**   | Satisfied for part of the declared scope only.                                                                                  |
| **NONCONFORMING**          | Applicable requirement demonstrably not satisfied.                                                                              |
| **INDETERMINATE**          | Applicability or satisfaction cannot be settled from the evidence available in this pass.                                       |
| **NOT APPLICABLE**         | Requirement addresses a construct this SDK does not implement or expose.                                                        |

This set is closed. Where a row needs a narrower reading than a bare state conveys, it
carries a **parenthetical qualifier** on one of these six — `CONFORMING (delegated)`,
`CONFORMING (with documented language limitation)` — never a new state. A qualifier is
part of the status and must be reproduced wherever the status is cited; dropping it
changes the claim.

### 1.3 Boundary of responsibility

`@pqc-sdk/core` does not implement lattice arithmetic itself. It is a wrapper: key
lifecycle, algorithm registry, envelope framing, AEAD sealing, and error mapping. The
arithmetic requirements of FIPS 203 §4–§7 are discharged — or not — by the primitive.
Rows are labelled **SDK**, **Vendored** or **Provider** in the _SDK Component_ column.

The distinction between the last two is what makes several rows closable at all, and it
must not be lost. The published `dist` imports `@noble/post-quantum` as an **external
runtime import** rather than inlining it, so consumers execute their own
registry-resolved copy. No patch, `overrides` entry, or `pnpm patchedDependencies` entry
in this repository can reach that copy — a **Provider**-scope finding is therefore not
closable from here at all.

**Vendored** rows are different. As of 2026-09-07 the ML-KEM surface of
`@noble/post-quantum@0.7.1` (`ml-kem.ts`, `_crystals.ts`, `utils.ts`) is copied into
`packages/core/src/vendor/ml-kem/` under its MIT license, and
`KEM_ALGORITHMS['ml-kem-768']` resolves to that copy. Because `src/` is bundled into
`dist` by tsup, a correction made there does ship to consumers.

As of 2026-09-09, `KEM_ALGORITHMS['x-wing']`'s embedded ML-KEM-768 also resolves to that
copy, via `packages/core/src/x-wing.ts` (see §3.10) — X-Wing's own X25519 component and
the generic hybrid combiner it uses (`combineKEMS`/`expandSeedXof`/`_ecdhKem`) still come
from the npm package and remain Provider-scope, since neither performs ML-KEM arithmetic
and neither carries an ML-KEM finding. ML-DSA is vendored separately (see
`FIPS-204-MATRIX.md` §1.3); SLH-DSA is not yet implemented by this SDK and, when it is,
will resolve entirely against the npm package and remain Provider-scope. See
`packages/core/src/vendor/ml-kem/NOTICE.md` for provenance, digests and the maintenance
procedure.

Vendoring is a maintenance liability, not a free win: it forks the ML-KEM
implementation, and every upstream release must now be re-vendored and re-verified
rather than picked up by a version bump. It was accepted here only because two `shall`
statements could not otherwise be satisfied for consumers by any means available to this
repository.

---

## 2. Compliance matrix

| Req ID      | FIPS 203 Quote                                                                                                                                                                                  | Section       | Normative Force     | Applicability                                             | SDK Component                                                                         | Evidence Required                                                                                                                                           | Current Status                                                                     |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **F203-01** | "ML-KEM comes equipped with three parameter sets: ML-KEM-512 (security category 1) • ML-KEM-768 (security category 3) • ML-KEM-1024 (security category 5)"                                      | §7 (intro)    | Definitional        | Project scope declares all three; FIPS mandates none      | `types.ts:7` (`KemAlgorithm`), `algorithms.ts:43` (`KEM_ALGORITHMS`)                  | Registry entry, exported type member, round-trip vector per set                                                                                             | **PARTIALLY CONFORMING** — see §3.1                                                |
| **F203-02** | "NIST recommends using ML-KEM-768 as the default parameter set, as it provides a large security margin at a reasonable performance cost."                                                       | §8            | Recommendation      | Applicable                                                | `algorithms.ts:76-86`                                                                 | The sole FIPS 203 set offered is 768; parameters match Table 2                                                                                              | **CONFORMING**                                                                     |
| **F203-03** | "a combined KEM that includes ML-KEM as a component might not meet IND-CCA2 security. Implementers should assess the security of any procedure in which …"                                      | §3.3          | SHOULD              | Applicable — `x-wing` is a combined KEM                   | `index.ts` (`FIPS_ALGORITHMS`, `SUPPORTED_ALGORITHMS`); `algorithms.ts:59-68`         | An exported constant (`FIPS_ALGORITHMS`) that excludes `x-wing` and names only NIST-standardized entries, with JSDoc citing FIPS 203 §3.3                   | **CONFORMING** — closed 2026-09-09 (corrective pass 2), see §3.2                   |
| **F203-04** | "(Type check) If ek is not an array of bytes of length 384k + 32 … then input checking failed."                                                                                                 | §7.2          | SHALL (via §3.3)    | Applicable                                                | `algorithms.ts` (`requireKey`); `vendor/ml-kem/ml-kem.ts` (`abytes` in `encapsulate`) | Negative test: wrong-length encapsulation key rejected with a documented `PqcError`                                                                         | **CONFORMING** — see §3.3                                                          |
| **F203-05** | "(Modulus check) Perform the computation test ← ByteEncode12(ByteDecode12(ek[0:384k])). If test ≠ ek[0:384k], then input checking failed."                                                      | §7.2          | SHALL (via §3.3)    | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`validateModulus`, invoked from `encapsulate`)             | Negative test: encapsulation key with a coefficient ≥ q injected and rejected at `encapsulate` — `fips203-input-checks.test.ts`                             | **CONFORMING** — closed 2026-09-09 (corrective pass 2), see §3.3                   |
| **F203-06** | "ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked as above."                                                                                                  | §7.2          | SHALL               | Applicable                                                | `encrypt.ts:41` → `algorithms.ts:153` (`requireKey`); `stream.ts:194,199`             | Both checks precede `Encaps_internal` on every call path                                                                                                    | **CONFORMING (delegated)**                                                         |
| **F203-07** | "Implementers shall ensure that ML-KEM.Encaps and ML-KEM.Decaps are only executed on inputs that have been checked, as described in Section 7."                                                 | §3.3          | SHALL               | Applicable                                                | `encrypt.ts:41,88`; `stream.ts:194,338`                                               | No call path reaches the primitive without traversing `requireKey`                                                                                          | **CONFORMING**                                                                     |
| **F203-08** | "(Ciphertext type check) If c is not a byte array of length 32(du·k + dv) … then input checking has failed." + "Ciphertext checking shall be performed with every execution of ML-KEM.Decaps."  | §7.3          | SHALL               | Applicable                                                | `encrypt.ts` (`minLength`), `vendor/ml-kem/ml-kem.ts` (`abytes` on `cipherText`)      | Negative test: truncated / over-length ciphertext rejected on every decapsulation                                                                           | **CONFORMING**                                                                     |
| **F203-09** | "(Decapsulation key type check) If dk is not a byte array of length 768k + 96 … then input checking has failed."                                                                                | §7.3          | SHALL (via §3.3)    | Applicable                                                | `algorithms.ts` (`requireKey`); `vendor/ml-kem/ml-kem.ts` (`abytes` on `secretKey`)   | Negative test: wrong-length decapsulation key rejected with a documented `PqcError`                                                                         | **CONFORMING**                                                                     |
| **F203-10** | "(Hash check) Perform the computation test ← H(dk[384k : 768k+32]). If test ≠ dk[768k+32 : 768k+64], then input checking has failed."                                                           | §7.3          | SHALL (via §3.3)    | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (hash check in `decapsulate`)                               | Negative test: stored `H(ek)` bit-flipped, `decapsulate` throws; stored hash independently verified against `SHA3-256(ek)` — `fips203-input-checks.test.ts` | **CONFORMING** — closed 2026-09-09 (corrective pass 2), see §3.3                   |
| **F203-11** | "2: if m == NULL then / 3: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                               | §7.2, Alg. 20 | Definitional        | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`sampleRandomness`), `algorithms.ts` (`encapsulateTo`)     | RBG failure surfaces as a distinct, non-key-attributed error condition                                                                                      | **CONFORMING** — closed 2026-09-07, see §3.4                                       |
| **F203-12** | "These random bytes shall be generated using an approved RBG, as prescribed in SP 800-90A, SP 800-90B, and SP 800-90C."                                                                         | §3.3          | SHALL               | Applicable to the deployed module; not determinable here  | Host runtime `crypto.getRandomValues` — outside this repository                       | An RBG validated under SP 800-90A/B/C, inside a cryptographic module boundary                                                                               | **INDETERMINATE** — reclassified 2026-09-08, see §3.5                              |
| **F203-13** | "this RBG shall have a security strength of at least … 192 bits for ML-KEM-768"                                                                                                                 | §3.3          | SHALL               | Applicable                                                | Host RBG (out of repository control)                                                  | Documented security-strength claim for the host entropy source on each supported runtime                                                                    | **INDETERMINATE** — depends on F203-12                                             |
| **F203-14** | "A fresh string of random bytes must be generated for every such invocation."                                                                                                                   | §3.3          | MUST (undefined)    | Applicable                                                | `encrypt.ts:53`; provider `Encaps` internal `m`                                       | No caching or reuse of encapsulation randomness across invocations                                                                                          | **NOT EVALUATED** — keyword unresolved                                             |
| **F203-15** | "The interfaces for these functions should not be made available to applications other than for testing purposes."                                                                              | §3.3          | SHOULD              | Applicable                                                | `keys.ts:60` (`generateKeyPairFromSeed`), `index.ts:22-34`                            | Seeded / derandomized entry points absent from the package export map                                                                                       | **CONFORMING** — see §3.6                                                          |
| **F203-16** | "the sampling of random values required for key generation … and encapsulation … shall be performed by the cryptographic module."                                                               | §3.3          | SHALL               | Applicable                                                | `keys.ts:53` (`randomBytes`), provider `Encaps`                                       | Randomness sampled inside the boundary, never supplied by the caller in production paths                                                                    | **CONFORMING**                                                                     |
| **F203-17** | "these values … can be used directly as a shared secret key for symmetric cryptography. If further key derivation is needed, the final symmetric keys shall be derived … in an approved manner" | §3.3          | SHALL (conditional) | Applicable                                                | `encrypt.ts:58` (`gcm(sharedSecret, …)`), `stream.ts`                                 | K used directly as an AES-256-GCM key; no non-approved KDF interposed                                                                                       | **CONFORMING** — see §3.7                                                          |
| **F203-18** | "implementers shall ensure that intermediate data is destroyed as soon as it is no longer needed … only the designated output can be retained in memory"                                        | §3.3, §6.3    | SHALL               | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`selectSharedSecret`, both `decapsulate` sites)            | Zeroization of intermediate state, including the implicit-reject flag                                                                                       | **CONFORMING (with documented language limitation)** — closed 2026-09-08, see §3.8 |
| **F203-19** | "Division and rounding in the computation of these functions are performed in the set of rational numbers. Floating-point computations shall not be used."                                      | §3.3, §4.2.1  | SHALL               | Applicable — `Compress_d` runs on every Encaps and Decaps | `vendor/ml-kem/ml-kem.ts` (`compress`)                                                | Integer-only implementation of Compress_d / Decompress_d                                                                                                    | **CONFORMING** — closed 2026-09-07, see §3.9                                       |
| **F203-20** | "The public-key encryption scheme K-PKE described in Section 5 shall not be used as a stand-alone cryptographic scheme."                                                                        | §3.3          | SHALL               | Applicable                                                | Public surface (`index.ts`), package export map                                       | No K-PKE entry point reachable from `@pqc-sdk/core`                                                                                                         | **CONFORMING**                                                                     |
| **F203-21** | "For every algorithm that is specified in this standard, a conforming implementation may replace the given set of steps with any mathematically equivalent set of steps."                       | §3.3          | MAY                 | Permissive — considered, and not relied on, for F203-19   | `vendor/ml-kem/ml-kem.ts` (`compress`)                                                | Proof of output equivalence over the full input domain                                                                                                      | **NOT APPLICABLE** — see §3.9                                                      |

### 4.2 Validation status

**No claim of FIPS validation is made or implied by this document.** Nothing in this
repository has been submitted to, or evaluated under, the NIST Cryptographic Module
Validation Program or the Cryptographic Algorithm Validation Program. This matrix
records the result of a self-assessment by static analysis. Conformance,
validation-readiness, and official validation status are three separate things, and
only the first is addressed here.

ACVP known-answer vectors (`packages/core/src/vectors/mlkem768-*.json`, exercised by
`nist-vectors.test.ts`) are assurance evidence. They demonstrate input/output agreement
with the standard on the tested paths. **They are not automatic proof of every internal
normative condition** — F203-19 is the standing counterexample: those vectors passed for
the entire period the requirement was breached, and still pass now that it is not. A
known-answer test cannot see the difference, which is exactly why closing that row
required a source-level assertion and not only a behavioural one.

The 31 ACVP cases now execute against the vendored primitive, because
`generateKeyPairFromSeed` and `pqc.decrypt` route through `algorithms.ts`. Their passing
is what establishes that vendoring changed no ML-KEM output.

### 4.3 Next actions (open)

1. ~~**F203-05, F203-10**~~ — closed 2026-09-09 (corrective pass 2): `fips203-input-checks.test.ts`
   exercises both checks directly. No further action.
2. **F203-18** — assessor decision on the proposed status (§3.8): `CONFORMING (with
documented language limitation)` as proposed, or `NONCONFORMING` on the ground that the
   `shall` cannot be met in a language with no zeroization primitive. No further code
   change is proposed either way.
3. ~~**F203-03**~~ — closed 2026-09-09 (corrective pass 2): `FIPS_ALGORITHMS` exported from
   `index.ts` with JSDoc citing FIPS 203 §3.3 and this matrix §3.2. No further action.
4. **F203-01** — expose ML-KEM-512 and ML-KEM-1024, with envelope/`headerId` allocation
   and its own requirement-by-requirement determination for each added set. The vendored
   module already exports `ml_kem512` and `ml_kem1024`; availability is not conformance,
   and each added set needs its own pass over this matrix.

### 4.4 Change log

| Date       | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-09-07 | Initial assessment. 21 rows recorded; F203-11, F203-12, F203-18, F203-19 NONCONFORMING.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 2026-09-07 | Corrective pass. ML-KEM surface vendored (§1.3); F203-11 and F203-19 closed with the evidence cited in §3.4, §3.9. Keyword-definition citation corrected from §1.3 to §2.1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 2026-09-08 | Corrective pass. F203-18: implicit-reject selection made branch-free at both `decapsulate` sites, both candidates now destroyed unconditionally; proposed **CONFORMING (with documented language limitation)**, pending assessor review (§3.8). F203-12: reclassified NONCONFORMING → INDETERMINATE — a classification correction, no code change; runtime randomness sources documented here and in `SECURITY.md` (§3.5). Qualifier convention recorded in §1.2.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 2026-09-09 | Corrective pass 1. Found and closed a scope gap (§3.10): X-Wing's embedded ML-KEM-768 — `pqc.keys.generate()`'s default path — still ran the unpatched floating-point `Compress_d` (F203-19) and the unpatched double-ternary implicit-reject selection (F203-18) after both rows had already closed for the `ml-kem-768` algorithm entry alone. `packages/core/src/x-wing.ts` repoints X-Wing at the vendored `ml_kem768`, reusing `@noble/post-quantum/hybrid.js`'s own `combineKEMS`/`expandSeedXof`/`_ecdhKem` (Provider-scope, no ML-KEM finding applies to them) rather than vendoring them; evidence in `x-wing.test.ts`. §1.3 and §3.2 updated to describe the new boundary. Row statuses for F203-03, F203-18 and F203-19 are unchanged by this pass.                                                                                                                                                    |
| 2026-09-09 | Adversarial verification pass. Found F203-11 had a second gap on X-Wing's default path. Closed by wrapping `encapsulate` in `x-wing.ts` to sample via `sampleRandomness` before the unpatched `combineKEMS` default parameter ever evaluates. Evidence: new default-path case in `rbg-attribution.test.ts`; `xwing-vectors.test.ts` 18 KAT cases re-verified unaffected. See §3.11.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 2026-09-09 | Corrective pass 2. Closed three open rows: **F203-03** — `FIPS_ALGORITHMS` constant exported from `index.ts`, listing only NIST-standardized entries (`ml-kem-768`, `ml-dsa-44/65/87`) and excluding `x-wing`, with JSDoc citing FIPS 203 §3.3 and this matrix §3.2; status INDETERMINATE → CONFORMING. **F203-05** — `fips203-input-checks.test.ts`: ML-KEM-768 encapsulation key with coefficient q=3329 injected; `encapsulate` throws; status CONFORMING (delegated) → CONFORMING. **F203-10** — same file: stored `H(ek)` bit-flipped in decapsulation key; `decapsulate` throws; stored hash re-derived independently and confirmed equal to `SHA3-256(ek)`; status CONFORMING (delegated) → CONFORMING. Also: F204-06/07 RBG path closed for ML-DSA (`keys.ts`, `sign.ts`); F204-05 hedged-signing test added; F204-09/21 provider tripwires added (`provider-tripwires.test.ts`). Summary counts updated. |
