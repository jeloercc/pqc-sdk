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

| Req ID      | FIPS 203 Quote                                                                                                                                                                                  | Section       | Normative Force     | Applicability                                             | SDK Component                                                                         | Evidence Required                                                                           | Current Status                                                                     |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **F203-01** | "ML-KEM comes equipped with three parameter sets: ML-KEM-512 (security category 1) • ML-KEM-768 (security category 3) • ML-KEM-1024 (security category 5)"                                      | §7 (intro)    | Definitional        | Project scope declares all three; FIPS mandates none      | `types.ts:7` (`KemAlgorithm`), `algorithms.ts:43` (`KEM_ALGORITHMS`)                  | Registry entry, exported type member, round-trip vector per set                             | **PARTIALLY CONFORMING** — see §3.1                                                |
| **F203-02** | "NIST recommends using ML-KEM-768 as the default parameter set, as it provides a large security margin at a reasonable performance cost."                                                       | §8            | Recommendation      | Applicable                                                | `algorithms.ts:44-53`                                                                 | The sole FIPS 203 set offered is 768; parameters match Table 2                              | **CONFORMING**                                                                     |
| **F203-03** | "a combined KEM that includes ML-KEM as a component might not meet IND-CCA2 security. Implementers should assess the security of any procedure in which …"                                      | §3.3          | SHOULD              | Applicable — `x-wing` is a combined KEM                   | `algorithms.ts:59-68`, `index.ts:63` (`SUPPORTED_ALGORITHMS`), `keys.ts:51`           | An API/documentation boundary that prevents `x-wing` being read as a FIPS 203 parameter set | **INDETERMINATE** — see §3.2                                                       |
| **F203-04** | "(Type check) If ek is not an array of bytes of length 384k + 32 … then input checking failed."                                                                                                 | §7.2          | SHALL (via §3.3)    | Applicable                                                | `algorithms.ts` (`requireKey`); `vendor/ml-kem/ml-kem.ts` (`abytes` in `encapsulate`) | Negative test: wrong-length encapsulation key rejected with a documented `PqcError`         | **CONFORMING** — see §3.3                                                          |
| **F203-05** | "(Modulus check) Perform the computation test ← ByteEncode12(ByteDecode12(ek[0:384k])). If test ≠ ek[0:384k], then input checking failed."                                                      | §7.2          | SHALL (via §3.3)    | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`validateModulus`, invoked from `encapsulate`)             | Negative test: encapsulation key with a coefficient ≥ q rejected fail-closed                | **CONFORMING (delegated)** — see §3.3                                              |
| **F203-06** | "ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked as above."                                                                                                  | §7.2          | SHALL               | Applicable                                                | `encrypt.ts:41` → `algorithms.ts:156`; `stream.ts:194,199`                            | Both checks precede `Encaps_internal` on every call path                                    | **CONFORMING (delegated)**                                                         |
| **F203-07** | "Implementers shall ensure that ML-KEM.Encaps and ML-KEM.Decaps are only executed on inputs that have been checked, as described in Section 7."                                                 | §3.3          | SHALL               | Applicable                                                | `encrypt.ts:41,88`; `stream.ts:194,338`                                               | No call path reaches the primitive without traversing `requireKey`                          | **CONFORMING**                                                                     |
| **F203-08** | "(Ciphertext type check) If c is not a byte array of length 32(du·k + dv) … then input checking has failed." + "Ciphertext checking shall be performed with every execution of ML-KEM.Decaps."  | §7.3          | SHALL               | Applicable                                                | `encrypt.ts` (`minLength`), `vendor/ml-kem/ml-kem.ts` (`abytes` on `cipherText`)      | Negative test: truncated / over-length ciphertext rejected on every decapsulation           | **CONFORMING**                                                                     |
| **F203-09** | "(Decapsulation key type check) If dk is not a byte array of length 768k + 96 … then input checking has failed."                                                                                | §7.3          | SHALL (via §3.3)    | Applicable                                                | `algorithms.ts` (`requireKey`); `vendor/ml-kem/ml-kem.ts` (`abytes` on `secretKey`)   | Negative test: wrong-length decapsulation key rejected with a documented `PqcError`         | **CONFORMING**                                                                     |
| **F203-10** | "(Hash check) Perform the computation test ← H(dk[384k : 768k+32]). If test ≠ dk[768k+32 : 768k+64], then input checking has failed."                                                           | §7.3          | SHALL (via §3.3)    | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (hash check in `decapsulate`)                               | Negative test: decapsulation key whose embedded `H(ek)` does not match is rejected          | **CONFORMING (delegated)** — see §3.3                                              |
| **F203-11** | "2: if m == NULL then / 3: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                               | §7.2, Alg. 20 | Definitional        | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`sampleRandomness`), `algorithms.ts` (`encapsulateTo`)     | RBG failure surfaces as a distinct, non-key-attributed error condition                      | **CONFORMING** — closed 2026-09-07, see §3.4                                       |
| **F203-12** | "These random bytes shall be generated using an approved RBG, as prescribed in SP 800-90A, SP 800-90B, and SP 800-90C."                                                                         | §3.3          | SHALL               | Applicable to the deployed module; not determinable here  | Host runtime `crypto.getRandomValues` — outside this repository                       | An RBG validated under SP 800-90A/B/C, inside a cryptographic module boundary               | **INDETERMINATE** — reclassified 2026-09-08, see §3.5                              |
| **F203-13** | "this RBG shall have a security strength of at least … 192 bits for ML-KEM-768"                                                                                                                 | §3.3          | SHALL               | Applicable                                                | Host RBG (out of repository control)                                                  | Documented security-strength claim for the host entropy source on each supported runtime    | **INDETERMINATE** — depends on F203-12                                             |
| **F203-14** | "A fresh string of random bytes must be generated for every such invocation."                                                                                                                   | §3.3          | MUST (undefined)    | Applicable                                                | `encrypt.ts:53`; provider `Encaps` internal `m`                                       | No caching or reuse of encapsulation randomness across invocations                          | **NOT EVALUATED** — keyword unresolved                                             |
| **F203-15** | "The interfaces for these functions should not be made available to applications other than for testing purposes."                                                                              | §3.3          | SHOULD              | Applicable                                                | `keys.ts:60` (`generateKeyPairFromSeed`), `index.ts:22-34`                            | Seeded / derandomized entry points absent from the package export map                       | **CONFORMING** — see §3.6                                                          |
| **F203-16** | "the sampling of random values required for key generation … and encapsulation … shall be performed by the cryptographic module."                                                               | §3.3          | SHALL               | Applicable                                                | `keys.ts:52` (`randomBytes`), provider `Encaps`                                       | Randomness sampled inside the boundary, never supplied by the caller in production paths    | **CONFORMING**                                                                     |
| **F203-17** | "these values … can be used directly as a shared secret key for symmetric cryptography. If further key derivation is needed, the final symmetric keys shall be derived … in an approved manner" | §3.3          | SHALL (conditional) | Applicable                                                | `encrypt.ts:58` (`gcm(sharedSecret, …)`), `stream.ts`                                 | K used directly as an AES-256-GCM key; no non-approved KDF interposed                       | **CONFORMING** — see §3.7                                                          |
| **F203-18** | "implementers shall ensure that intermediate data is destroyed as soon as it is no longer needed … only the designated output can be retained in memory"                                        | §3.3, §6.3    | SHALL               | Applicable                                                | `vendor/ml-kem/ml-kem.ts` (`selectSharedSecret`, both `decapsulate` sites)            | Zeroization of intermediate state, including the implicit-reject flag                       | **CONFORMING (with documented language limitation)** — closed 2026-09-08, see §3.8 |
| **F203-19** | "Division and rounding in the computation of these functions are performed in the set of rational numbers. Floating-point computations shall not be used."                                      | §3.3, §4.2.1  | SHALL               | Applicable — `Compress_d` runs on every Encaps and Decaps | `vendor/ml-kem/ml-kem.ts` (`compress`)                                                | Integer-only implementation of Compress_d / Decompress_d                                    | **CONFORMING** — closed 2026-09-07, see §3.9                                       |
| **F203-20** | "The public-key encryption scheme K-PKE described in Section 5 shall not be used as a stand-alone cryptographic scheme."                                                                        | §3.3          | SHALL               | Applicable                                                | Public surface (`index.ts`), package export map                                       | No K-PKE entry point reachable from `@pqc-sdk/core`                                         | **CONFORMING**                                                                     |
| **F203-21** | "For every algorithm that is specified in this standard, a conforming implementation may replace the given set of steps with any mathematically equivalent set of steps."                       | §3.3          | MAY                 | Permissive — considered, and not relied on, for F203-19   | `vendor/ml-kem/ml-kem.ts` (`compress`)                                                | Proof of output equivalence over the full input domain                                      | **NOT APPLICABLE** — see §3.9                                                      |

---

## 3. Finding detail

### 3.1 F203-01 — Parameter-set exposure

One of the three FIPS 203 parameter sets is reachable.

| Parameter set | Registered | Public API | Provider export          |
| ------------- | ---------- | ---------- | ------------------------ |
| ML-KEM-512    | No         | No         | `ml_kem512` — available  |
| ML-KEM-768    | **Yes**    | **Yes**    | `ml_kem768`              |
| ML-KEM-1024   | No         | No         | `ml_kem1024` — available |

`algorithms.ts:44-53` matches FIPS 203 Table 3 for ML-KEM-768 exactly: encapsulation
key 1184 bytes, decapsulation key 2400 bytes, ciphertext 1088 bytes.

Two points must be kept apart, and this matrix keeps them apart deliberately:

- **Against FIPS 203 itself, this is not a nonconformity.** The standard defines three
  parameter sets; it does not require an implementation to provide all three. A module
  implementing only ML-KEM-768 is a conforming ML-KEM-768 implementation.
- **Against the declared project scope, it is a shortfall.** The project's completion
  target covers all three sets, and the pinned provider already exports `ml_kem512`
  and `ml_kem1024`. The gap is exposure, not availability.

The blocker is type-level rather than data-level: `types.ts:7` declares
`KemAlgorithm = 'ml-kem-768' | 'x-wing'`, so `KEM_ALGORITHMS` is a `Record` over a
closed union. Adding a set is a type change plus an envelope/`headerId` allocation in
`docs/serialization-format.md`, not a registry line.

**Availability in the provider proves availability only. It is not evidence of
conformance for the added set**; each new parameter set requires its own
requirement-by-requirement determination against this matrix.

### 3.2 F203-03 — X-Wing segregation

`x-wing` (`draft-connolly-cfrg-xwing-kem-10`, X25519 + ML-KEM-768) is registered as a
peer of `ml-kem-768` in the same `KEM_ALGORITHMS` record, appears in the same
`SUPPORTED_ALGORITHMS` array, and is the **default** returned by `generate()`
(`keys.ts:51`).

It is a CFRG Internet-Draft construction. **It is not a FIPS 203 algorithm and must not
be counted toward FIPS 203 coverage**, notwithstanding that ML-KEM-768 is one of its
components.

Nothing in the current API expresses that boundary. A caller reading
`SUPPORTED_ALGORITHMS = ['ml-kem-768', 'ml-dsa-65', 'x-wing']` alongside a package
description naming "FIPS 203/204" has no signal distinguishing the standardized entries
from the draft one. The status is recorded as **INDETERMINATE** rather than
nonconforming because FIPS 203 §3.3 imposes a `should`-level assessment duty on
implementers, not a labelling duty — but the absence of segregation is what prevents
this row from being settled.

Suggested direction, for a later remediation PR: an explicit standardization-status
field on the algorithm spec, or a separate exported constant partitioning FIPS-approved
from draft algorithms. Not actioned in this pass.

**Update, 2026-09-09.** X-Wing's embedded ML-KEM-768 component now resolves to the
vendored, FIPS-corrected copy (`vendor/ml-kem/ml-kem.ts`) rather than to
`@noble/post-quantum`'s own internal one — see `packages/core/src/x-wing.ts`, and §3.10
for why this was needed and what it closed. This was done for **engineering reasons**:
keeping the two known ML-KEM defects (F203-19, F203-18) fixed on the code path
`pqc.keys.generate()` actually uses by default, since a downstream consumer's shared
secret does not carry a label saying which named algorithm produced it. **It is not, and
must not be read as, a claim of FIPS 203 coverage for X-Wing.** X-Wing is still a CFRG
Internet-Draft construction, still not a FIPS 203 algorithm, and this row's status is
unchanged by that work — **INDETERMINATE**, for the same segregation reason recorded
above. Correcting the component ML-KEM-768's arithmetic method does not change what
X-Wing _is_; X-Wing counted for nothing toward FIPS 203 coverage before this change and
counts for nothing toward it now.

### 3.3 F203-04, F203-05, F203-10 — Input validation on the encapsulation path

The validation chain preceding `Encaps_internal` has two independent layers, both
present:

**Layer 1 — SDK boundary.** `requireKey` (`algorithms.ts:104-127`), invoked at
`encrypt.ts:41` and `stream.ts:194`:

- algorithm-kind mismatch → `PqcError('WRONG_ALGORITHM')`
- key-use mismatch → `PqcError('WRONG_KEY_USE')`
- `key.bytes.length !== 1184` → `PqcError('INVALID_KEY')`

**Layer 2 — delegated to the primitive**, in `encapsulate`:

- `abytes(publicKey, lengths.publicKey, 'publicKey')` — FIPS 203 §7.2 type check
- `validateModulus(publicKey, 'encapsulate')` — FIPS 203 §7.2 modulus check, the
  `ByteEncode12(ByteDecode12(ek))` round-trip

The corresponding decapsulation checks (§7.3) are likewise present: ciphertext length in
`encrypt.ts` (`minLength`) and again via `abytes` in `decapsulate`, decapsulation-key
length via `abytes`, and the embedded `H(ek)` hash check.

Since 2026-09-07 this layer is the vendored `vendor/ml-kem/ml-kem.ts` rather than
`node_modules`. The checks themselves were copied unmodified — the vendoring changed
where the code lives, not what it verifies.

**Correction of a premise carried into this assessment.** The reverted patch sometimes
cited in connection with "public key length validation" concerned **ML-DSA
verification** — FIPS 204 §3.6.2, where `ML-DSA.Verify` is required to _return `false`_
rather than throw on a wrong-length verification key — and touched `sign.ts` plus a
`requireVerificationKey` helper. **It never modified the ML-KEM encapsulation path.**
Its reversion therefore introduced no ML-KEM length-validation gap, and none exists:
both FIPS 203 §7.2 input checks execute before any cryptographic work.

**What is genuinely missing is objective evidence, not logic.** Rows F203-05 and
F203-10 are marked _CONFORMING (delegated)_ precisely because their satisfaction rests
on source inspection of a dependency rather than on a test in this repository:

| Check                               | Repository evidence                                               |
| ----------------------------------- | ----------------------------------------------------------------- |
| §7.2 step 1 — ek type check         | `encrypt.test.ts:58` — wrong-length key → `INVALID_KEY`           |
| §7.2 step 2 — ek modulus check      | **None.** No test constructs a key with a coefficient ≥ q         |
| §7.3 step 1 — ciphertext type check | `encrypt.test.ts` header/length cases; `stream-mutations.test.ts` |
| §7.3 step 2 — dk type check         | `encrypt.test.ts:58` pattern via `requireKey`                     |
| §7.3 step 3 — dk hash check         | **None.** No test tampers `dk[768k+32 : 768k+64]`                 |

The bit-flip matrix in `key-mutations.test.ts:97-140` does not fill these gaps: it
asserts that a tampered key never yields a decryptable ciphertext, which a random
single-bit flip in a 1184-byte encapsulation key will almost never achieve _by way of_
the modulus check. The property under test is different from the property claimed.

This matters beyond bookkeeping. Both checks live in a pinned dependency; a version
bump that relaxed either would ship green through the current gate. Under the
project's mutation-check discipline, a test guarding a cryptographic property must fail
when the property is broken — these two currently would not.

### 3.4 F203-11 — RBG failure misattributed as an invalid encapsulation key

**Status: CLOSED 2026-09-07. Severity when open: low (diagnostic integrity). Never
exploitable; not a key-recovery or forgery issue.**

FIPS 203 Algorithm 20 separates two distinct failure conditions. Input checking is
performed _before_ the algorithm runs (§7.2), while random-bit-generation failure is a
condition _inside_ it, returning `⊥` at steps 2–4.

**The defect, as found.** `encapsulateTo` collapsed the two:

```ts
try {
  return spec.kem.encapsulate(publicKey);
} catch (cause) {
  if (cause instanceof PqcError) {
    throw cause;
  }
  throw new PqcError('INVALID_KEY', `${algorithm} public key is not a valid encapsulation key`);
}
```

The encapsulation randomness `m` is sampled **inside** `spec.kem.encapsulate()`. An
entropy failure — `crypto.getRandomValues` absent or throwing, which is a live
possibility on hardened runtimes and on the Cloudflare Workers and React Native targets
this SDK claims — is therefore caught by the same handler and reported to the operator
as a malformed _recipient key_. During an entropy outage the SDK directs the
investigation at key distribution.

The catch-all itself is deliberate and correct in origin: `algorithms.ts` documents that
it exists to stop raw `@noble/curves` errors, thrown for degenerate X25519 points on the
X-Wing path, from reaching callers — consistent with the project's rule that errors carry
only lengths, algorithm names, and key use. The remedy was therefore to **narrow** the
handler, not to remove it.

**The correction, as applied.** Discriminating on the host's error message would have
been brittle, so the vendored primitive raises a dedicated type instead:

- `vendor/ml-kem/ml-kem.ts` adds `RbgFailureError` and a `sampleRandomness(n)` helper
  that wraps the two `randomBytes(msgLen)` call sites — the plain `encapsulate` and the
  `prepare().encapsulate` variant. It maps both a throw and a short or absent return to
  that type, the latter standing in for the standard's literal `m == NULL` test.
- `errors.ts` adds the `RBG_FAILURE` code to `PqcErrorCode`.
- `encapsulateTo` gains an `instanceof RbgFailureError` branch **before** the catch-all.
  Order is the whole point: specific first, so the general case cannot swallow it.

Only the module-sampled branch changed. A caller-supplied deterministic message (the
test-vector hook) is untouched, and the thrown message carries the algorithm name and a
byte count — no host error text, no key material.

**Objective evidence.** `packages/core/src/vendor/ml-kem/__tests__/rbg-attribution.test.ts`,
9 cases, all passing:

| Test name                                                                      | What it establishes                                                             |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `encapsulateTo surfaces RBG_FAILURE when the platform RBG throws`              | The host generator raising is attributed correctly                              |
| `… when the platform RBG absent`                                               | `crypto.getRandomValues` missing entirely — the Workers/RN case                 |
| `… when the platform RBG short`                                                | A host returning a truncated buffer (`m == NULL` in substance)                  |
| `reports RBG_FAILURE through the public pqc.encrypt entry point too`           | The code reaches real callers, not just the internal helper                     |
| `the RBG_FAILURE message leaks no key material, only the failure and a length` | The no-secrets-in-output rule holds on the new path                             |
| `a valid key still encapsulates normally once the RBG works again`             | The failures came from the stub, not a broken fixture                           |
| `encapsulateTo still maps a zero pk_X to INVALID_KEY` (+ `one`)                | The X-Wing degenerate-point mapping is intact — the load-bearing non-regression |
| `a wrong-length ML-KEM public key still maps to INVALID_KEY`                   | The §7.2 type check still wins over the new branch                              |

The last three are the ones that matter for review: the obvious way to get this wrong is
to widen the new branch until it captures cases that genuinely _are_ invalid keys.

### 3.5 F203-12, F203-13 — Approved RBG

**Status: reclassified NONCONFORMING → INDETERMINATE on 2026-09-08. This is a correction
of the classification, not a change in the code or an improvement in conformance.**

FIPS 203 §3.3: "These random bytes shall be generated using an approved RBG, as
prescribed in SP 800-90A, SP 800-90B, and SP 800-90C. Moreover, this RBG shall have a
security strength of at least 128 bits for ML-KEM-512, at least 192 bits for ML-KEM-768,
and at least 256 bits for ML-KEM-1024."

**Why the previous label was wrong.** `NONCONFORMING` is defined in §1.2 as "applicable
requirement demonstrably not satisfied". Nothing here was demonstrated. The requirement
constrains the _source_ of the randomness — the generator behind
`crypto.getRandomValues` — which is a property of the host runtime, not of any code in
this repository. This assessment cannot show that source is unapproved any more than it
can show it is approved; it has no visibility into it at all. `INDETERMINATE`
("applicability or satisfaction cannot be settled from the evidence available in this
pass") is the state that actually describes the situation, and it is already the label
carried by the dependent row F203-13.

**What the SDK does control, it does.** Randomness is drawn fresh per invocation, sampled
inside the module rather than accepted from callers on any production path (F203-16), and
since 2026-09-07 a failure of the platform generator surfaces as `RBG_FAILURE` rather
than being misreported as an invalid key (F203-11). None of that makes the source
approved.

**Where the bytes come from, per supported runtime.** Documented so the delegation is
explicit; this table asserts **nothing** about SP 800-90 approval status:

| Runtime                          | Randomness API resolved at run time                                              |
| -------------------------------- | -------------------------------------------------------------------------------- |
| Node 20+                         | `globalThis.crypto.getRandomValues` (Web Crypto, backed by OpenSSL `RAND_bytes`) |
| Deno                             | `globalThis.crypto.getRandomValues`                                              |
| Cloudflare Workers               | `globalThis.crypto.getRandomValues` (workerd)                                    |
| React Native (Expo)              | `react-native-get-random-values` → `SecRandomCopyBytes` / `SecureRandom`         |
| Hermes standalone (example only) | **`Math.random`** — not cryptographically secure; engine-validation harness only |

The Hermes row is recorded because omitting it would be the dishonest choice.
`examples/hermes-standalone/shims.js` fills bytes from `Math.random` and says so in its
own comment; it exists to prove the engine can execute the SDK, and is not a usable
configuration. A real React Native app uses the Expo row's polyfill.

`crypto.getFips()` returns `0` on the assessed Node runtime, which is a fact about that
host, not a determination about the requirement.

**Why no code change can settle this.** An approved RBG under SP 800-90A/B/C entails a
validated entropy source and a cryptographic-module construction. A JavaScript library
does not acquire either by calling a host API. FIPS 203 makes the same delegation on its
own cover page, point 13: "conformance to this standard does not ensure that a particular
implementation is secure… The responsible authority in each agency or department shall
ensure that an overall implementation provides an acceptable level of security." The
duty-holder for this requirement is whoever deploys the complete module.

F203-13 (security strength ≥ 192 bits for ML-KEM-768) remains INDETERMINATE for the same
reason and is conditioned on F203-12: with no approved RBG established in the boundary
there is no claimable security-strength figure, only the host's undocumented one.

Recorded for deployers in `SECURITY.md` § "Randomness source". **Reclassification is not
progress**: see §4.1, where this row is still called out as the requirement most likely
to matter to a downstream compliance reviewer and the one that cannot be closed here.

### 3.6 F203-15 — Controlled access to derandomized interfaces

Correct posture. `generateKeyPairFromSeed` (`keys.ts:60`) is not re-exported from
`index.ts:22-34`, and `packages/core/package.json` declares a single `"."` export with
no subpath. The seeded interface is reachable from the test suite and from the golden
vector scripts, and not from consumers. `KEM_ALGORITHMS` and `encapsulateTo` are
likewise unexported, so the optional derandomization seed on
`NobleKem.encapsulate(publicKey, seed?)` (`algorithms.ts:21-24`) is not reachable
either.

One documentation defect, recorded here because it touches this row's evidence and not
because it is a FIPS 203 matter: the JSDoc example on `encapsulateTo`
(`algorithms.ts:140-148`) reads
`import { KEM_ALGORITHMS, encapsulateTo } from '@pqc-sdk/core';`. Neither identifier is
exported from that entry point, so the example does not compile as written. The project
requires every public function's JSDoc example to compile; `encapsulateTo` is not a
public function, which is exactly why the example is wrong.

### 3.7 F203-17 — Use of the shared secret

`encrypt.ts:58` passes the 32-byte shared secret directly to
`gcm(sharedSecret, nonce, header)`. FIPS 203 §3.3 permits this explicitly — the values
"can be used directly as a shared secret key for symmetric cryptography" — and the
`shall`-clause on approved derivation binds only when further derivation is performed.
No KDF is interposed. **Conforming.**

One defense-in-depth observation, outside the requirement: the SDK does not assert the
shared-secret length before use. `gcm()` accepts 16-, 24-, and 32-byte keys, so the
"AES-256-GCM" property rests entirely on the primitive returning 32 bytes. FIPS 203
states the 256-bit output descriptively and imposes no caller-side check, so this is not
a nonconformity — but an explicit length assertion would convert an assumption into a
guarantee at negligible cost.

### 3.8 F203-18 — Destruction of intermediate values

**Status: CLOSED 2026-09-08, with a documented language limitation — see the caveat at
the end of this section, which is part of the disposition and not a footnote to it.**

The outputs are not in scope. SP 800-227 §3.2 states that the outputs of a KEM algorithm
are **not** intermediate values. The shared secret, the ciphertext and the plaintext held
by `encrypt.ts` are outputs; their retention is not a §3.3 breach, and no zeroization
obligation attaches to the SDK for them. (An earlier analysis over-scoped this row by
treating them as intermediates. That was withdrawn.)

The correct target is the implicit-reject flag. FIPS 203 §6.3, on step 9 of
ML-KEM.Decaps_internal: "The 'implicit reject' flag computed in step 9 (by comparing c
and c′) is a secret piece of intermediate data. As specified in the requirements in
Section 3.3, this flag shall be destroyed prior to ML-KEM.Decaps_internal terminating. In
particular, returning the value of the flag as an output in any form is not permitted."

**Two things were already correct and were not touched.**

- `equalBytes` in the vendored `utils.ts` is a proper constant-time comparison: it walks
  the whole array accumulating `diff |= a[i] ^ b[i]` with no early return. It was never
  the defect.
- The flag was never returned, in any form. The final sentence of §6.3 was already met.

**The defect, as found.** The flag was consumed by two ternaries in each of the two
`decapsulate` implementations:

```ts
cleanBytes(msg, cipherText2, kr.subarray(32), !isValid ? Khat : Kbar);
return (isValid ? Khat : Kbar) as TRet<Uint8Array>;
```

Those are source-level control-flow decisions whose condition is secret intermediate
data, and what they decide is _which heap object survives the call_. That is precisely
the class of observable the Fujisaki-Okamoto implicit-reject construction exists to
neutralise — the flag is not "destroyed" in any meaningful sense while the shape of the
computation still depends on it.

**The correction, as applied.** A new `selectSharedSecret(isValid, Khat, Kbar)` helper
combines the two candidates byte-wise under an arithmetic mask, into a fresh buffer:

```ts
const mask = -Number(isValid) & 0xff;
const out = new Uint8Array(32);
for (let i = 0; i < 32; i++) out[i] = (onValid[i] & mask) | (onReject[i] & ~mask & 0xff);
```

Every output byte is now computed from both inputs. Because the returned value is a
detached buffer rather than one of the candidates, the question "which one do we
destroy?" disappears: both are destroyed unconditionally, and the second ternary goes
with it.

Applied at **both** call sites — `decapsulate` and `prepare().decapsulate`. The work
order showed only one; there are two, mirroring the two `encapsulate` sites corrected for
F203-11.

**Objective evidence.** `packages/core/src/vendor/ml-kem/__tests__/implicit-reject.test.ts`,
9 cases, all passing:

| Test name                                                                      | What it establishes                                                                                                   |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `the valid path still reproduces every ACVP encapsulation vector`              | The match branch of the mask is byte-identical to the previous ternary                                                |
| `the reject path returns exactly J(z ‖ c), computed independently in the test` | The reject value is unchanged, checked against SHAKE256 derived from the standard rather than from the implementation |
| `never throws on a corrupted ciphertext — it implicitly rejects`               | The construction still fails closed silently, at four tamper positions                                                |
| `is deterministic on the reject path`                                          | The mask mixes in no fresh state                                                                                      |
| `the prepared decapsulate path agrees with the plain one on both branches`     | The second call site carries the identical correction                                                                 |
| `zeroizes both shared-secret candidates, not only the non-returned one`        | The return value is a detached 32-byte buffer, so widening the destruction did not zero it                            |
| `does not leave H(ek) or the public key mutated in the caller's secret key`    | The widened `cleanBytes` did not start reaching into caller-owned memory                                              |
| `decapsulate selects through the mask helper, not a ternary on isValid`        | No secret-dependent branch remains in the source; both sites use the helper                                           |
| `the mask yields exactly one candidate for every byte pair`                    | The selection is exhaustively correct over all 131,072 `(flag, a, b)` combinations                                    |

The second row is the one that matters most: agreeing with the previous implementation
would only show the change was inert. Deriving `J(z ‖ c)` independently from Algorithm 18
step 10 shows the reject path returns the _right_ value, not merely the same one.

**The limitation, which is part of this disposition and must be cited with it.** The
existing comment in the vendored file — "JS/JIT still provides no constant-time guarantees
for that path" — remains true after this correction, and was kept rather than softened.
What changed is that no explicit source-level branch decides which object survives. What
did **not** change:

- JavaScript exposes no comparison or selection primitive with a verifiable
  constant-time guarantee at the hardware level.
- A JIT may still specialise on observed values, so the compiled path is not provably
  branch-free even where the source is.
- `isValid` is a primitive boolean and cannot be zeroized the way a `Uint8Array` can.
  Nothing in the language permits "destroying" it in the sense §6.3 has in mind.

These are properties of the execution environment, not residual defects in this function,
and no change to this repository can remove them. **This row is therefore not
100% closed**, and the qualifier in its status is load-bearing.

**On the status label.** The methodology (§1.2) defines a closed set of six states and
this pass does not add a seventh. `CONFORMING` is used with the parenthetical qualifier
"(with documented language limitation)", by the same convention already in use for
`CONFORMING (delegated)` — a qualifier on an existing state, not a new state. The
reasoning for choosing it over the alternatives:

- Not `NONCONFORMING`: the specific defect identified under this requirement — branching
  on the secret flag — has been removed and the removal is evidenced.
- Not plain `CONFORMING`: that would assert the requirement is fully discharged, which
  would overstate what a JavaScript implementation can demonstrate.
- Not `INDETERMINATE`: applicability and the state of the code are both settled; nothing
  here is unresolved for want of evidence.

**This proposal is submitted for review rather than treated as final.** If the assessor
prefers `NONCONFORMING` on the ground that a `shall` about destroying secret intermediate
data cannot be met at all in a garbage-collected language with no zeroization primitive,
that reading is defensible and the evidence above supports it equally well — the facts do
not change, only the label. What must not happen is the qualifier being dropped and the
row being read as plainly conforming.

**Scope.** This closed the row for the `ml-kem-768` algorithm entry on 2026-09-08.
**X-Wing's embedded ML-KEM-768 was not covered at the time** — it continued to run the
unpatched double-ternary selection this row describes as closed, until 2026-09-09; see
§3.10 for that gap and its closure. ML-DSA and SLH-DSA remain Provider-scope for this
requirement, not closable from this repository (§1.3).

### 3.9 F203-19 — Floating-point arithmetic in Compress_d

**Status: CLOSED 2026-09-07.**

FIPS 203 states the prohibition twice, unconditionally. §3.3: "No floating-point
arithmetic. Implementations of ML-KEM shall not use floating-point arithmetic, as
rounding errors in floating-point operations may lead to incorrect results in some
cases." §4.2.1, for `Compress_d`/`Decompress_d` specifically: "Floating-point
computations shall not be used." Both are `shall` (§2.1) — requirements. The functions
execute on **every** ML-KEM encapsulation and decapsulation as part of ciphertext
compression (for ML-KEM-768, `du = 10` and `dv = 4`, both `< 12`).

**The defect, as found**, in `@noble/post-quantum@0.7.1` `ml-kem.ts`:

```ts
encode: (i: number) => ((i << d) + Q / 2) / Q,
```

`Q` is 3329, so `Q / 2` evaluates to `1664.5` — a non-integer IEEE-754 double — and the
outer `/ Q` is likewise double division. In JavaScript, `/` is always floating-point
division; the presence or absence of `Math.*` is not a test for this requirement, and
treating it as one produces a false negative. `decode` was already integer-only (`>>> d`)
and was correct as it stood.

**The correction, as applied**, in `vendor/ml-kem/ml-kem.ts`:

```ts
encode: (i: number) => Number((2n * (BigInt(i) << bigD) + bigQ) / twoQ),
```

BigInt has no floating-point representation and its `/` truncates toward zero, so no
rounding error is representable. The identity used is
`round_half_up(a / b) = floor((2a + b) / 2b)` for `a, b >= 0`, with `a = i · 2^d` and
`b = Q` — which is FIPS 203 §4.2.1's `round((2^d / q) · x)` evaluated over the rationals.

One contract change is worth flagging to reviewers: upstream `encode` returned an
_unrounded double_ (e.g. `0.5`) and relied on every caller applying `& getMask(d)` to
truncate it. The replacement returns the already-floored integer, so it agrees with
upstream _after_ masking, not before. That is safe because both call sites mask —
`bitsCoder` does `c.encode(...) & mask`, and `__tests.Compress_d` does `& getMask(d)` —
and it is the better contract, since the value is now a Z_(2^d) member as defined.

**Functional impact: none.** This was verified, not assumed.

**Objective evidence.** `packages/core/src/vendor/ml-kem/__tests__/compress-equivalence.test.ts`,
6 cases, all passing. The domain is enumerated exhaustively rather than sampled: `q = 3329`
and `d ∈ [1, 11]` gives 3329 × 11 = **36,619 pairs**, small enough for CI, so nothing is
probabilistic.

| Test name                                                                           | What it establishes                                                             |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `matches the original floating-point implementation on all 36,619 domain pairs`     | The change is output-inert: 0 discrepancies against the code it replaced        |
| `matches the FIPS 203 §4.2.1 definition evaluated in exact rational arithmetic`     | Both versions are actually _correct_, not merely in agreement                   |
| `always lands inside Z_(2^d), as the standard requires of the output`               | Output type conformance across the full domain                                  |
| `satisfies the FIPS 203 §4.2.1 round-trip property Compress_d(Decompress_d(y)) = y` | The stated property of the pair, catching a change to either half               |
| `is genuinely mutation-sensitive: a wrong rounding rule is detected`                | Guards the suite itself — truncation instead of round-half-up must be caught    |
| `does not use floating-point arithmetic in the compression source`                  | Asserts on the source text, since this requirement is about method, not outcome |

The second and sixth rows carry the weight. Agreeing with the old code only proves the
change was inert; it does not prove either version was ever right — hence the independent
exact-rational reference. And because the old code was _also_ bit-exact yet still breached
the standard, no behavioural test can detect a regression here: only reading the source
can, which is what the sixth test does.

F203-21 (the "mathematically equivalent set of steps" allowance, §3.3) remains
**NOT APPLICABLE**. It was not used as a mitigation while this row was open, and it is not
retroactively credited now. That allowance permits substituting equivalent _steps_; it
does not lift an explicit prohibition on the arithmetic _medium_, and reading it as a
waiver for §4.2.1 would let output equivalence override a requirement written precisely
because output equivalence is not the concern.

Closed for consumers, not merely locally: the fix lives in `src/`, which tsup bundles into
`dist`. Had it been applied to `node_modules` it would have closed nothing (§1.3).

**Scope, added 2026-09-09.** This closed the row for the `ml-kem-768` algorithm entry on
2026-09-07. **X-Wing's embedded ML-KEM-768 was not covered at the time** — it continued
to run the unpatched floating-point `encode: (i) => ((i << d) + Q / 2) / Q` this row
describes as closed, until 2026-09-09; see §3.10 for that gap and its closure.

### 3.10 F203-19, F203-18 — the gap in X-Wing's embedded ML-KEM-768

**Status: gap existed 2026-09-07 (F203-19) / 2026-09-08 (F203-18) through 2026-09-09;
closed 2026-09-09.**

Both §3.8 and §3.9 were marked CONFORMING as soon as the vendored copy existed and each
row's test suite passed against it — correctly, for the `ml-kem-768` algorithm entry.
Neither closure examined any other registry entry. `x-wing` (`KEM_ALGORITHMS['x-wing']`)
is `pqc.keys.generate()`'s **default** (`keys.ts:51`), and until 2026-09-09 it was built
from `@noble/post-quantum/hybrid.js`'s own `ml_kem768_x25519` preset, which constructs its
embedded ML-KEM-768 from that package's _own_ internal, unpatched `ml-kem.ts`
(`hybrid.ts` imports it as `import { ml_kem1024, ml_kem768 } from './ml-kem.ts'`) — not
from `vendor/ml-kem/ml-kem.ts`. So for the entire period spanning both closures, the
default key-generation path in this SDK still executed, on every X-Wing encapsulation and
decapsulation:

- the floating-point `Compress_d` expression `((i << d) + Q / 2) / Q` that §3.9 records
  as closed for `ml-kem-768`, and
- the double-ternary implicit-reject/zeroization selection
  (`!isValid ? Khat : Kbar` / `isValid ? Khat : Kbar`) that §3.8 records as closed for
  `ml-kem-768`.

Confirmed by tracing the call path, not inferred from the two sharing a package:
`combineKEMS`'s `encapsulate`/`decapsulate` call `rawKems[i].encapsulate(...)` /
`.decapsulate(...)` directly on whichever `ml_kem768` object the preset was built with
(`hybrid.ts:549,577`), and the npm package's own `ml-kem.ts` still contains both
unpatched expressions verbatim at the pinned `0.7.1` version.

**Why the earlier closures did not catch this.** §1.2's rule — a row moves to CONFORMING
only on a named, executed test — was followed for the `ml-kem-768` entry specifically;
nothing in that rule required re-checking every other registry entry that happens to
embed the same primitive under a different name. The gap was found on 2026-09-09, during
a review of this matrix's own scoping, prompted by the observation that X-Wing embeds
ML-KEM-768 and that FIPS 203 §3.3's combined-KEM language (cited at F203-03/§3.2) says
nothing that would have extended either row's closure to a non-FIPS composite — the two
closures were correct on their own terms and simply never scoped to ask the question.

**The fix.** `packages/core/src/x-wing.ts` reconstructs `ml_kem768_x25519` from
`@noble/post-quantum/hybrid.js`'s own public `combineKEMS`, `expandSeedXof` and
`_ecdhKem` exports — verbatim, same argument order, same hard-coded domain-separation
label — substituting the vendored `ml_kem768` for the npm-internal one. None of those
three combiner functions perform ML-KEM arithmetic, so neither F203-19 nor F203-18
applies to them, and none needed vendoring. `algorithms.ts`'s `x-wing` entry now imports
`ml_kem768_x25519` from that module instead of from `@noble/post-quantum/hybrid.js`.

**Objective evidence.** `packages/core/src/x-wing.test.ts`, 6 cases: identical component
`lengths` between the two presets; identical keys, ciphertext and shared secret between
the vendored-backed and npm-backed presets under matched deterministic seeds (proving the
swap changed method, not output — the same argument already established for the
standalone rows in §3.8/§3.9, extended here to the composite); a bidirectional round-trip
(vendored-encapsulated ↔ npm-decapsulated, and the reverse) showing existing X-Wing keys
and ciphertexts remain valid; and a tampered-ciphertext case showing both implementations
implicitly reject to the same (wrong) secret. The pre-existing `xwing-vectors.test.ts`
(draft-10 Appendix C KAT vectors) and `properties.test.ts`'s X-Wing property suite
continue to pass unchanged through the repointed path.

**Scope, restated.** This closes the gap for ML-KEM-768's floating-point and
implicit-reject behavior wherever it is embedded in this repository's registry —
`ml-kem-768` directly, and now `x-wing`'s component. It does **not** extend FIPS 203
coverage to X-Wing itself (§3.2), and it does not touch X-Wing's X25519 component or its
combiner (`combineKEMS`/`expandSeedXof`/`_ecdhKem`, still sourced from
`@noble/post-quantum/hybrid.js`), which perform no ML-KEM arithmetic, carry no FIPS 203
finding, and remain Provider-scope. SLH-DSA is unaffected and remains Provider-scope; it
does not embed ML-KEM.

---

## 4. Summary

As of the 2026-09-08 corrective pass (F203-18 closed with a qualifier, F203-12
reclassified):

| Status                                           | Count  | Req IDs                                                                         |
| ------------------------------------------------ | ------ | ------------------------------------------------------------------------------- |
| CONFORMING                                       | 9      | F203-02, F203-04, F203-07, F203-08, F203-09, F203-11, F203-16, F203-17, F203-19 |
| CONFORMING (delegated)                           | 4      | F203-05, F203-06, F203-10, F203-15                                              |
| CONFORMING (with documented language limitation) | 1      | F203-18 — **proposed, pending assessor review (§3.8)**                          |
| PARTIALLY CONFORMING                             | 1      | F203-01                                                                         |
| NONCONFORMING                                    | 0      | —                                                                               |
| INDETERMINATE                                    | 3      | F203-03, F203-12, F203-13                                                       |
| NOT EVALUATED                                    | 1      | F203-14                                                                         |
| NOT APPLICABLE                                   | 1      | F203-21                                                                         |
| **Total**                                        | **21** |                                                                                 |

Previous states: 2026-09-07 assessment pass — CONFORMING 7, NONCONFORMING 4.
2026-09-07 corrective pass — CONFORMING 9, NONCONFORMING 2.

**The NONCONFORMING count reaching zero does not mean the SDK is FIPS 203 compliant, and
this table must not be cited to that effect.** One of the two rows that left that column
did so by _reclassification_ rather than by any change to the code (F203-12), and the
other carries a qualifier recording a limitation that no change to this repository can
remove (F203-18). Read §4.1 before quoting any number from this table.

### 4.1 Aggregate-score caution

The counts above are an inventory, not a score. They must not be reduced to a
percentage or a pass mark. The rows are not of equal weight, they do not share a single
duty-holder, and they are not equally closable:

- **F203-12** moved out of NONCONFORMING by **reclassification, not remediation**. Not one
  line of code changed for it. It is not closable by any change to this repository — an
  approved RBG requires a validated entropy source and a cryptographic-module boundary,
  which no JavaScript library obtains by calling a host API. Treating its move as progress
  would invert the meaning of the change.
- **F203-18** is closed for ML-KEM only, and only with its qualifier. The qualifier
  records that JavaScript offers no verifiable constant-time primitive and no way to
  zeroize a primitive boolean — limits the correction did not and cannot remove (§3.8).
  Its status is also **proposed, not settled**: §3.8 sets out why `NONCONFORMING` remains
  a defensible reading and invites the assessor to choose. It stays Provider-scope for
  ML-DSA and SLH-DSA. It no longer stays Provider-scope for X-Wing's embedded
  ML-KEM-768 as of 2026-09-09 — that component-level gap existed from this row's closure
  until then and is recorded, with dates, in §3.10.
- **F203-01** is a project-scope shortfall, not a FIPS 203 breach.
- **F203-05** and **F203-10** are counted as conforming, but on delegated evidence only.
  Rows moving to CONFORMING in later passes does not make the remaining delegated rows
  any better evidenced than they were.

An empty NONCONFORMING column is not a licence to read the table as "compliant". The
single requirement most likely to matter to a downstream compliance reviewer — F203-12, an
approved RBG — is the one that cannot be settled here at all, and it is now INDETERMINATE
precisely because this assessment has no visibility into it. Two rows also remain
unevidenced beyond source inspection (F203-05, F203-10), one is unresolved on keyword
interpretation (F203-14), and one parameter set of three is exposed (F203-01).

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

### 4.3 Next actions (not performed in this pass)

1. **F203-05, F203-10** — add mutation tests for the §7.2 modulus check and the §7.3
   hash check, converting two delegated rows into evidenced ones. Now cheaper than when
   first recorded: the code under test is in `src/`, so a test can reach it directly
   rather than through a dependency.
2. **F203-18** — assessor decision on the proposed status (§3.8): `CONFORMING (with
documented language limitation)` as proposed, or `NONCONFORMING` on the ground that the
   `shall` cannot be met in a language with no zeroization primitive. No further code
   change is proposed either way.
3. **F203-03** — express the FIPS-approved / draft boundary in the public API so
   `x-wing` cannot be read as a FIPS 203 parameter set.
4. **F203-01** — expose ML-KEM-512 and ML-KEM-1024, with envelope/`headerId` allocation
   and its own requirement-by-requirement determination for each added set. The vendored
   module already exports `ml_kem512` and `ml_kem1024`; availability is not conformance,
   and each added set needs its own pass over this matrix.

### 4.4 Change log

| Date       | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-09-07 | Initial assessment. 21 rows recorded; F203-11, F203-12, F203-18, F203-19 NONCONFORMING.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 2026-09-07 | Corrective pass. ML-KEM surface vendored (§1.3); F203-11 and F203-19 closed with the evidence cited in §3.4, §3.9. Keyword-definition citation corrected from §1.3 to §2.1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 2026-09-08 | Corrective pass. F203-18: implicit-reject selection made branch-free at both `decapsulate` sites, both candidates now destroyed unconditionally; proposed **CONFORMING (with documented language limitation)**, pending assessor review (§3.8). F203-12: reclassified NONCONFORMING → INDETERMINATE — a classification correction, no code change; runtime randomness sources documented here and in `SECURITY.md` (§3.5). Qualifier convention recorded in §1.2.                                                                                                                                                                                                                                                                                                                                                                           |
| 2026-09-09 | Corrective pass. Found and closed a scope gap (§3.10): X-Wing's embedded ML-KEM-768 — `pqc.keys.generate()`'s default path — still ran the unpatched floating-point `Compress_d` (F203-19) and the unpatched double-ternary implicit-reject selection (F203-18) after both rows had already closed for the `ml-kem-768` algorithm entry alone. `packages/core/src/x-wing.ts` repoints X-Wing at the vendored `ml_kem768`, reusing `@noble/post-quantum/hybrid.js`'s own `combineKEMS`/`expandSeedXof`/`_ecdhKem` (Provider-scope, no ML-KEM finding applies to them) rather than vendoring them; evidence in `x-wing.test.ts`. §1.3 and §3.2 updated to describe the new boundary. Row statuses for F203-03, F203-18 and F203-19 are unchanged by this pass — see §3.2 for why closing the gap is not a FIPS 203 coverage claim for X-Wing. |
