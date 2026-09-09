# FIPS 204 (ML-DSA) — Conformance Matrix

**Object of assessment:** `@pqc-sdk/core` @ `0.8.3`, commit `3d76be9`, branch `main`
**Normative document:** FIPS 204, _Module-Lattice-Based Digital Signature Standard_
(NIST, 13 August 2024)
**Primitive provider:** `@noble/post-quantum@0.7.1` (exact pin), ML-DSA resolves to the npm
package — **not** vendored, unlike ML-KEM (see §1.3)
**Assessment dates:** 2026-09-08 (registry pass — Phase 1, Stage 2); 2026-09-08
(conformity pass — Phase 2); 2026-09-08 (corrective pass — F204-08); 2026-09-09
(corrective pass — F204-01, F204-04 — see §4.4)
**Method:** static source analysis of `packages/core/src` and of the pinned provider,
supplemented by direct runtime probes against the built `dist` for rows where reading alone
could not settle behaviour (F204-06/07, F204-08 — see §3.3, §3.4). The registry and
conformity passes changed no code; the corrective pass changed `sign.ts` and `sign.test.ts`
only, for F204-08.

---

## 1. Scope and reading instructions

This matrix records, requirement by requirement, the state of FIPS 204 conformance for the
ML-DSA surface of `packages/core`. It is the FIPS 204 counterpart of
`docs/compliance/FIPS-203-MATRIX.md` and uses the same eight columns, the same status
vocabulary, and the same evidence discipline. Row identifiers use the `F204-` prefix.

The Phase 1 registry pass changed nothing and evaluated nothing. This Phase 2 pass assigns
a conformity state to all 22 rows, each with a file/line or test-name citation. A row is
`CONFORMING` only where evidence in this repository supports it; where the evidence is
source inspection of the provider rather than a test here, the row carries the
`(delegated)` qualifier.

Quotations are copied verbatim from the standard. Where a requirement is too long to quote
whole, the operative fragment — the `shall`/`should` and its immediate context — is quoted
and the remainder referenced by section number. No requirement is paraphrased into the
Quote column.

### 1.1 Keyword semantics

FIPS 204 §2.1 (Terms and Definitions) defines exactly two normative keywords, identically to
FIPS 203:

> `shall` — Used to indicate a requirement of this standard.
> `should` — Used to indicate a strong recommendation but not a requirement of this
> standard. Ignoring the recommendation could lead to undesirable results.

`must` is **not** defined by FIPS 204, yet appears 13 times in the body — including in a
normative-sounding position in §5.4 ("the hash or XOF of the content to be signed must be
computed within a FIPS 140-validated cryptographic module"). Statements resting solely on an
undefined `must` carry `MUST (undefined)` in the _Normative Force_ column and are **not**
treated as discharged or as breached; their interpretation remains open. This is the same
Class M treatment used in the FIPS 203 matrix.

### 1.2 Status vocabulary

Identical to `FIPS-203-MATRIX.md` §1.2, with one state made explicit:

| Status                     | Meaning                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **CONFORMING**             | Requirement is applicable, satisfied, and supported by objective evidence in this repository.                                   |
| **CONFORMING (delegated)** | Requirement is satisfied by the pinned provider, verified by source inspection, but not guarded by any test in this repository. |
| **PARTIALLY CONFORMING**   | Satisfied for part of the declared scope only.                                                                                  |
| **NONCONFORMING**          | Applicable requirement demonstrably not satisfied.                                                                              |
| **INDETERMINATE**          | Applicability or satisfaction cannot be settled from the evidence available in this pass.                                       |
| **NOT EVALUATED**          | Applicable, but no determination has been attempted yet.                                                                        |
| **NOT APPLICABLE**         | Requirement addresses a construct this SDK does not implement or expose.                                                        |

`NOT EVALUATED` is distinct from `INDETERMINATE`: the former means nobody has looked, the
latter means someone looked and the evidence could not settle it. No row in this document
is `NOT EVALUATED` any longer.

This set is closed. Where a row needs a narrower reading than a bare state conveys, it
carries a **parenthetical qualifier** on one of these seven — never a new state. A qualifier
is part of the status and must be reproduced wherever the status is cited.

> **Divergence to reconcile.** `FIPS-203-MATRIX.md` §1.2 lists six states and omits
> `NOT EVALUATED`, yet its §4 summary table assigns that status to F203-14. The definition
> above is the intended one; the FIPS 203 document should be amended to match. Flagged, not
> fixed — that file is out of scope for this pass.

### 1.3 Boundary of responsibility

`@pqc-sdk/core` does not implement lattice arithmetic itself. It is a wrapper: key lifecycle,
algorithm registry, context-string validation, and error mapping. The arithmetic requirements
of FIPS 204 §6–§7 are discharged — or not — by the primitive. Rows are labelled **SDK** or
**Provider** in the _SDK Component_ column.

**ML-DSA is Provider-scope in a way ML-KEM no longer is, and this governs two rows in this
pass.** `algorithms.ts:2` imports `ml_dsa65` from `@noble/post-quantum/ml-dsa.js`. The
published `dist` keeps that as an external runtime import, so consumers execute their own
registry-resolved copy and no patch, `overrides` entry, or `pnpm patchedDependencies` entry
in this repository can reach it. The ML-KEM surface was vendored into
`packages/core/src/vendor/ml-kem/` precisely to escape that constraint; **the ML-DSA surface
was not**.

F204-10 and F204-13 are therefore recorded as **NONCONFORMING (provider-scope, not closable
from this repository)**. That qualifier is load-bearing in both directions: the requirement
is demonstrably not satisfied, _and_ no change to `packages/core/src` can satisfy it absent a
decision to vendor `ml-dsa.ts` — a decision outside this assessment's scope. Neither row is a
defect in code this repository authored.

F204-08 was the opposite case and must not be confused with them: **SDK-scope**, located in
`sign.ts`, and closable here — as it now has been (§3.4).

### 1.4 Structural differences from FIPS 203

| Area                            | FIPS 203                   | FIPS 204                                                       |
| ------------------------------- | -------------------------- | -------------------------------------------------------------- |
| Additional-requirements section | §3.3                       | §3.6, with four numbered subsections                           |
| RBG strength per parameter set  | one `shall` threshold each | ML-DSA-44 carries a `should` **and** a `shall` (F204-04)       |
| Randomness inside the operation | `m` in Encaps — `shall`    | `rnd` in Sign — `should`, with `may` fallback (F204-05)        |
| Intermediate-value destruction  | KeyGen/Encaps/Decaps       | extends explicitly to **verification** (F204-10)               |
| Signing variants                | none                       | hedged vs deterministic, §3.4 (F204-14, F204-15)               |
| Pre-hash variant                | none                       | HashML-DSA, §5.4 with its own Algorithms 4–5 (F204-17…F204-20) |
| Length checks                   | fail-closed on input check | `shall return false`, not throw (F204-08)                      |

---

## 2. Compliance matrix

| Req ID      | FIPS 204 Quote                                                                                                                                                                                                 | Section                   | Normative Force      | Applicability                                                                   | SDK Component                                                                  | Evidence Required                                                                                            | Current Status                                                         |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | -------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| **F204-01** | "Three ML-DSA parameter sets are included in Table 1." + "ML-DSA-44 is claimed to be in security strength category 2, ML-DSA-65 is claimed to be in category 3, and ML-DSA-87 is claimed to be in category 5"  | §4, Tables 1–2            | Definitional         | Project scope declares all three; FIPS mandates none                            | `types.ts:10`, `algorithms.ts:104-129`                                         | Registry entry, exported type member, Table 2 byte lengths, ACVP round-trip per set                          | **CONFORMING** — all 3 sets exposed and evidenced; see §3.1            |
| **F204-02** | "The seed 𝜉 shall be a fresh (i.e., not previously used) random value generated using an approved RBG, as prescribed in SP 800-90A, SP 800-90B, and SP 800-90C"                                                | §3.6.1                    | SHALL                | Applicable to the deployed module; source is the host runtime                   | `keys.ts:53` (`randomBytes(spec.seedLength)`)                                  | Freshness per invocation **and** an RBG validated under SP 800-90A/B/C inside a module boundary              | **INDETERMINATE** — freshness met, approval not determinable; see §3.2 |
| **F204-03** | "the RBG used shall have a security strength of at least 192 bits for ML-DSA-65 and 256 bits for ML-DSA-87"                                                                                                    | §3.6.1                    | SHALL                | Both clauses applicable — ML-DSA-65 and ML-DSA-87 are both registered           | Host RBG — outside repository control                                          | Documented security-strength claim for the host entropy source on each supported runtime                     | **INDETERMINATE** — see §3.2                                           |
| **F204-04** | "For ML-DSA-44, the RBG should have a security strength of at least 192 bits and shall have a security strength of at least 128 bits."                                                                         | §3.6.1                    | SHOULD + SHALL       | Applicable — ML-DSA-44 is now registered                                        | Host RBG — outside repository control                                          | Documented security-strength claim for the host entropy source on each supported runtime                     | **INDETERMINATE** — activated 2026-09-09; see §3.1                     |
| **F204-05** | "While this value should ideally be generated by an approved RBG, other methods for generating fresh random values may be used."                                                                               | §3.6.1                    | SHOULD + MAY         | Applicable — the SDK signs in hedged mode only                                  | `sign.ts:45`; provider `sign` → `randomBytes(signRandBytes)` (`ml-dsa.js:453`) | `rnd` freshly generated per signature; approval is a recommendation, and `may` permits other fresh sources   | **CONFORMING** — the `may` clause is met; see §3.2                     |
| **F204-06** | "2: if 𝜉 = NULL then / 3: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                                               | §5.1, Alg. 1              | Definitional         | Applicable                                                                      | `keys.ts:50-53`, provider `keygen` (`ml-dsa.js:363-368`)                       | RBG failure during key generation produces an error indication and yields no key                             | **CONFORMING (delegated)** — see §3.3                                  |
| **F204-07** | "6: if 𝑟𝑛𝑑 = NULL then / 7: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                                             | §5.2, Alg. 2 (and Alg. 4) | Definitional         | Applicable for Alg. 2; Alg. 4 not exposed                                       | `sign.ts:44-45`, provider `sign` (`ml-dsa.js:450-454`)                         | RBG failure during signing produces an error indication and yields no signature                              | **CONFORMING (delegated)** — see §3.3                                  |
| **F204-08** | "If an implementation of ML-DSA can accept inputs for 𝜎 or 𝑝𝑘 of any other length, it shall return false whenever the lengths of either of these inputs differ from their lengths specified in this standard." | §3.6.2                    | SHALL                | Applicable — `verify` accepts caller-supplied σ and pk                          | `sign.ts` (`hasWrongVerificationKeyLength`, called from `verify`)              | Wrong-length σ **and** wrong-length pk each cause `verify` to **return `false`** — not to throw              | **CONFORMING** — closed 2026-09-08; see §3.4                           |
| **F204-09** | "implementations of ML-DSA shall ensure that any potentially sensitive intermediate data is destroyed as soon as it is no longer needed."                                                                      | §3.6.3                    | SHALL                | Applicable                                                                      | Provider `keygen` / `sign` internals (14 `cleanBytes` sites, `ml-dsa.js`)      | Zeroization of expanded private-key polynomials, `rnd`, and signing scratch state                            | **CONFORMING (delegated)** — see §3.5                                  |
| **F204-10** | "The data used internally by verification algorithms is similarly sensitive for some applications… Intermediate values of the verification algorithm may reveal information about its inputs"                  | §3.6.3                    | SHALL (per F204-09)  | Applicable — no FIPS 203 equivalent                                             | `vendor/ml-dsa/ml-dsa.ts` (`internal.verify`, try/finally)                     | Zeroization on the verification path too, not only keygen/signing                                            | **CONFORMING** — closed 2026-09-08; see §3.5                           |
| **F204-11** | "As the seed can be used to compute the private key, it is sensitive data and shall be treated with the same safeguards as a private key."                                                                     | §3.6.3, case 1            | SHALL                | Applicable — `generateKeyPairFromSeed` takes a seed                             | `keys.ts:60`, absent from `index.ts:22-34` and from the `"."`-only export map  | The seed is not exposed to consumers, and is handled with private-key safeguards wherever retained           | **CONFORMING** — see §3.5                                              |
| **F204-12** | "the matrix 𝐀̂ is data that is easily computed from the public key and does not require any special protections."                                                                                               | §3.6.3, case 2            | Permissive           | **Not applicable** — grants a permission, imposes no duty                       | Provider internals                                                             | —                                                                                                            | **NOT APPLICABLE** — see §3.5                                          |
| **F204-13** | "Implementations of ML-DSA shall not use floating-point arithmetic, as rounding errors in floating point operations may lead to incorrect results in some cases."                                              | §3.6.4                    | SHALL                | Applicable                                                                      | `vendor/ml-dsa/ml-dsa.ts` (`decompose`, `Power2Round`, `HINT_M`, `GAMMA2_1/2`) | Integer-only implementation of Algorithms 35–38                                                              | **CONFORMING** — closed 2026-09-08; see §3.6                           |
| **F204-14** | "the lack of randomness in the deterministic variant makes the risk of side-channel attacks (particularly fault attacks) more difficult to mitigate. Therefore, this variant should not be used…"              | §3.4                      | SHOULD NOT           | **Not applicable** — deterministic variant is unreachable                       | `sign.ts:14-25` (`toNobleOptions` rebuilds the options object)                 | —                                                                                                            | **NOT APPLICABLE** — see §3.7                                          |
| **F204-15** | "Only implementing the hedged variant (i.e., without the deterministic variant) is sufficient to guarantee interoperability."                                                                                  | §3.4                      | Permissive           | Applicable                                                                      | `sign.ts:39-46` (`sign`)                                                       | Hedged-only exposure is a complete implementation; ACVP sigVer vectors verify externally produced signatures | **CONFORMING** — see §3.7                                              |
| **F204-16** | "1: if \|𝑐𝑡𝑥\| > 255 then / 2: return ⊥ ▷ return an error indication if the context string is too long"                                                                                                        | §5.2, Alg. 2              | Definitional         | Applicable — the SDK exposes an optional context                                | `sign.ts:6` (`MAX_CONTEXT_LENGTH`), `sign.ts:18-23`, `sign.ts:70`              | Contexts over 255 bytes refused on **both** sign and verify, with a documented `PqcError`                    | **CONFORMING** — see §3.8                                              |
| **F204-17** | "If the default 'hedged' variant of is used, the 32-byte random value 𝑟𝑛𝑑 shall be generated by the cryptographic module that generates the signature"                                                         | §5.4                      | SHALL                | **Not applicable** — SDK does not expose HashML-DSA                             | Provider `prehash()` (`ml-dsa.js:666`) — unreferenced by this SDK              | —                                                                                                            | **NOT APPLICABLE** — see §3.9                                          |
| **F204-18** | "the hash or XOF of the content to be signed must be computed within a FIPS 140-validated cryptographic module"                                                                                                | §5.4                      | MUST (undefined)     | **Not applicable** — SDK does not expose HashML-DSA                             | Provider `prehash()` — unreferenced by this SDK                                | —                                                                                                            | **NOT APPLICABLE** — see §3.9                                          |
| **F204-19** | "the digest that is signed needs to be generated using an approved hash function or XOF … that provides at least 𝜆 bits of classical security strength against both collision and second preimage attacks"     | §5.4                      | Undefined ("needs")  | **Not applicable** — SDK does not expose HashML-DSA                             | Provider `prehash(hash)` — unreferenced by this SDK                            | —                                                                                                            | **NOT APPLICABLE** — see §3.9                                          |
| **F204-20** | "While a single key pair may be used for both ML-DSA and HashML-DSA signatures, it is recommended that each key pair only be used for one version or the other."                                               | §5.4                      | MAY + Recommendation | **Not applicable** — SDK does not expose HashML-DSA                             | `keys.ts:50` (`generate`)                                                      | —                                                                                                            | **NOT APPLICABLE** — see §3.9                                          |
| **F204-21** | "This standard makes use of the functions SHAKE256 and SHAKE128, as defined in FIPS 202" + "This standard will always call these functions with an output length of a multiple of eight bits"                  | §3.7                      | Definitional         | Applicable                                                                      | Provider `ml-dsa.js` → `@noble/hashes/sha3.js` (`shake256`, `shake128`)        | SHAKE256/SHAKE128 are the FIPS 202 functions, byte-oriented                                                  | **CONFORMING (delegated)** — see §3.10                                 |
| **F204-22** | "When a public-key certificate is not available, users of digital signatures should determine whether a public key needs to be bound to an identity."                                                          | §3.5                      | SHOULD               | **Not applicable** — addressed to users; the SDK implements no identity binding | No PKI, certificate or identity surface in `packages/core/src`                 | —                                                                                                            | **NOT APPLICABLE** — see §3.10                                         |

---

## 3. Determination detail

### 3.1 F204-01, F204-04 — Parameter sets

**Status: F204-01 CLOSED 2026-09-09 (all three sets exposed and evidenced). F204-04
activated 2026-09-09 and determined INDETERMINATE — see the second half of this section.**

**The Stage 2 flag is resolved.** `algorithms.ts` declared `readonly signer: typeof ml_dsa65`
— a **concrete** type, not a structural interface — which made adding a second parameter set
a type change, not a registry line. It is now `NobleSigner`, a structural interface mirroring
`NobleKem`'s role on the KEM side: it declares only `keygen`, `sign` and `verify`, the three
methods the SDK actually calls, and any `@noble` signer object matching that shape satisfies
it regardless of which parameter set built it. `types.ts` widens
`SignatureAlgorithm` from the closed single-member union `'ml-dsa-65'` to
`'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87'`.

| Parameter set | Exported by the provider     | Registered in the SDK | Reachable by a consumer |
| ------------- | ---------------------------- | --------------------- | ----------------------- |
| ML-DSA-44     | `ml_dsa44` (`ml-dsa.js:718`) | **Yes**               | **Yes**                 |
| ML-DSA-65     | `ml_dsa65` (`ml-dsa.js:728`) | **Yes**               | **Yes**                 |
| ML-DSA-87     | `ml_dsa87` (`ml-dsa.js:738`) | **Yes**               | **Yes**                 |

`SIGNATURE_ALGORITHMS` (`algorithms.ts:104-129`) now carries all three entries, each pointing
at the vendored `getDilithium(...)` closure for its parameter set (`vendor/ml-dsa/ml-dsa.ts`),
with byte lengths read from the provider at runtime rather than assumed — pulled directly from
`ml_dsa44.lengths` / `ml_dsa65.lengths` / `ml_dsa87.lengths` and cross-checked against FIPS 204
Table 2 before registering them:

| Set       | seed | publicKey | secretKey | signature |
| --------- | ---- | --------- | --------- | --------- |
| ML-DSA-44 | 32   | 1312      | 2560      | 2420      |
| ML-DSA-65 | 32   | 1952      | 4032      | 3309      |
| ML-DSA-87 | 32   | 2592      | 4896      | 4627      |

**Both corrections apply to all three sets, verified by reading the source, not inferred from
the fact that all three share a package.** `ml_dsa44`, `ml_dsa65` and `ml_dsa87` are each built
by an independent call to the same `getDilithium(opts)` factory
(`vendor/ml-dsa/ml-dsa.ts:974,986,998`), and both F204-13's integer-only `decompose`/
`Power2Round` and F204-10's `finally`-block zeroization in `internal.verify` are defined once,
inside that factory's body (`ml-dsa.ts:315` onward, `:864-871`) — not reimplemented
per parameter set. Every call to `getDilithium` gets an independent closure over identical
corrected logic, parameterized only by `GAMMA2`/`ETA`/etc., not by which correction runs.
`vendor/ml-dsa/__tests__/rounding-equivalence.test.ts` already exercises this directly: its
`decompose` suite runs both the ML-DSA-44 gamma2 (95232) and the ML-DSA-65/87 gamma2 (261888)
cases across the complete domain.

**ACVP round-trip evidence, per set — mandatory for this closure, not follow-up work.** All
six vector files share the same provenance as the original `mldsa65-*.json` pair: NIST's
official ACVP-Server repository (`github.com/usnistgov/ACVP-Server`,
`gen-val/json-files/ML-DSA-keyGen-FIPS204/` and `.../ML-DSA-sigVer-FIPS204/`), recorded in each
file's own `"source"` field. `mldsa44-keygen.json` and `mldsa87-keygen.json` take the first 5
of that source's 25 keyGen test-group cases per set, matching the existing `mldsa65-keygen.json`
precedent exactly (same source, same "first 5" selection). `mldsa44-sigver.json` and
`mldsa87-sigver.json` take **all 15** cases from each set's `signatureInterface: "external"`,
`preHash: "pure"` test group — a superset of `mldsa65-sigver.json`'s 11-of-15 selection, chosen
because the per-set case ordering is randomized upstream (verified — the three groups do not
share a mutation-category sequence), so there is no faithful way to reproduce the exact same
11-case cut for the new sets; taking the full group is simpler, reproducible, and strictly more
evidence. Wired into `nist-vectors.test.ts` as one `describe` block per set (parametrized over
`ML_DSA_SETS`, replacing three copies of near-identical code with one loop).

| Set       | keyGen cases | sigVer cases | Test result               |
| --------- | ------------ | ------------ | ------------------------- |
| ML-DSA-44 | 5            | 15           | 20/20 passing             |
| ML-DSA-65 | 5            | 11           | 16/16 passing (unchanged) |
| ML-DSA-87 | 5            | 15           | 20/20 passing             |

**Result: CONFORMING, not merely PARTIALLY CONFORMING-closed-by-fiat.** FIPS 204 defines three
parameter sets and does not require an implementation to provide all three — a module
implementing only ML-DSA-65 was, and remains, a conforming ML-DSA-65 implementation. What
changes the status here is that the row is scored against the _declared project scope_
(`CLAUDE.md`'s "Algorithms (implemented)" line, updated in this pass from ML-DSA-65 alone to
"ML-DSA-44/65/87"), and that scope is now fully met with objective evidence per set, not
merely provider availability
(§3.1's own opening rule from Stage 2 still holds: availability in the provider is not evidence
of conformance).

**F204-04 activates as a direct consequence, and is determined here rather than inherited
silently.** Its thresholds are ML-DSA-44-specific ("For ML-DSA-44, the RBG should have a
security strength of at least 192 bits and shall have a security strength of at least 128
bits."); with ML-DSA-44 now registered and reachable, the row addresses a construct this SDK
does expose, so `NOT APPLICABLE` no longer fits. **INDETERMINATE, for the same reason F204-02
and F204-03 are** (§3.2): the `shall`/`should` constrain the _source_ of the randomness — the
generator behind `crypto.getRandomValues` — which is a property of the host runtime, not of
any code in this repository. This assessment has no visibility into that source's approved
security strength and can no more show it meets the 128-bit `shall` floor than it can show it
fails it; `NONCONFORMING` would require demonstrating non-satisfaction, and nothing was
demonstrated. The consequence clause travels with the row rather than being dropped: "If an
approved RBG with at least 128 bits of security but less than 192 bits of security is used,
then the claimed security strength of ML-DSA-44 is reduced from category 2 to category 1" —
also indeterminate, for the identical reason.

**F204-03's applicability text is corrected in the same pass.** Its quote already covered both
ML-DSA-65 (192 bits) and ML-DSA-87 (256 bits); the row's Applicability column previously read
"ML-DSA-65 applicable; ML-DSA-87 not registered" because ML-DSA-87 was not exposed when that
row was written. It is now registered, so both clauses are applicable. The row's determination
does not change — it was already `INDETERMINATE` for the ML-DSA-65 clause alone, for the same
host-visibility reason that now governs both clauses uniformly.

### 3.2 F204-02, F204-03, F204-05 — Randomness

**F204-02 and F204-03 are INDETERMINATE for the same reason F203-12 is**, and the
classification is imported deliberately rather than re-derived. The `shall` constrains the
_source_ of the randomness — the generator behind `crypto.getRandomValues` — which is a
property of the host runtime. This assessment has no visibility into it and can no more show
it unapproved than approved. `NONCONFORMING` would require demonstrating non-satisfaction;
nothing was demonstrated.

The freshness half of F204-02 _is_ satisfied and is recorded as such: `keys.ts:53` calls
`randomBytes(spec.seedLength)` on every `generate()`, with no caching or reuse path. The
approval half is what leaves the row unsettled. Runtime randomness sources per supported
target are documented in `SECURITY.md` § "Randomness source"; that table asserts nothing about
SP 800-90 approval status.

**Corrected 2026-09-09:** F204-03's ML-DSA-87 clause was inert here through the row's original
determination, because ML-DSA-87 was not registered at the time. It is now registered (§3.1),
so both the ML-DSA-65 and ML-DSA-87 clauses are applicable. The row's determination is
unchanged by that — it was already `INDETERMINATE` on the ML-DSA-65 clause alone, for the host-
visibility reason above, which governs the ML-DSA-87 clause identically.

**F204-05 is CONFORMING, and its weaker force is why.** FIPS 204 makes approval a `should` for
`rnd`, then explicitly permits alternatives: "other methods for generating fresh random values
may be used", adding that "even a weak RBG may be preferable to the fully deterministic
variants". The SDK never passes `extraEntropy` (§3.7), so the provider draws
`randomBytes(signRandBytes)` fresh per signature at `ml-dsa.js:453`. Fresh random values are
used, which is what the `may` clause requires.

The `should`-level preference for an approved RBG remains indeterminate for the same host
reason as F204-02 — but a recommendation left unmet is not a requirement breached, and the
standard's own `may` clause forecloses reading it as one. **Do not import the ML-KEM `shall`
onto this row**; FIPS 203 §3.3 makes the encapsulation randomness `m` a `shall`, and this is
not that.

**Evidence gap recorded, not credited:** no test in this repository asserts that two
signatures over the same message with the same key differ — i.e. that signing is actually
hedged rather than deterministic. The row rests on provider source inspection.

### 3.3 F204-06, F204-07 — RBG failure indication

Stage 2 warned against assuming the ML-KEM `RBG_FAILURE` work covers these. **That warning
was correct, and it is confirmed by direct probe**, not by reading alone. With
`crypto.getRandomValues` stubbed to throw, against the built `dist`:

| Call                                            | Result                          |
| ----------------------------------------------- | ------------------------------- |
| `pqc.keys.generate({ algorithm: 'ml-dsa-65' })` | `Error: entropy pool exhausted` |
| `pqc.sign('msg', secretKey)`                    | `Error: entropy pool exhausted` |
| `pqc.encrypt(...)` — ML-KEM baseline            | `PqcError(RBG_FAILURE)`         |

The `RbgFailureError` type and the `RBG_FAILURE` mapping live in
`packages/core/src/vendor/ml-kem/ml-kem.ts` and `algorithms.ts` (`encapsulateTo`) respectively,
and reach only the ML-KEM path. ML-DSA key generation (`keys.ts:53`) and signing
(`sign.ts:45`) have no equivalent wrapper.

**Both rows are nevertheless CONFORMING (delegated), and the reasoning matters.** Algorithm 1
step 3 and Algorithm 2 step 7 both say "return ⊥ ▷ return an error indication if random bit
generation failed". FIPS 204 requires _an error indication_. It does not prescribe the error's
type, nor that it be distinguishable from other failures. A thrown `Error` is an error
indication, and both calls fail closed — no key, no signature is produced. The requirement is
met.

> **Observation, recorded separately because it is not a FIPS 204 breach.** A raw upstream
> `Error` escaping `pqc.keys.generate` and `pqc.sign` does violate this project's own rule in
> `.claude/rules/crypto-review.md` — "never a raw upstream `@noble` error leaking through" —
> and it is inconsistent with the ML-KEM path, where the same condition yields
> `PqcError('RBG_FAILURE')`. That is an SDK-scope quality and consistency gap, closable in
> `keys.ts` and `sign.ts` without touching the provider. It is deliberately **not** counted as
> a nonconformity in the table above, because inflating a repo-rule deviation into a standards
> breach is the failure mode this programme has repeatedly had to correct.

Neither row is guarded by a test in this repository; hence `(delegated)`.

### 3.4 F204-08 — Public-key and signature length checks

**This resolves the "reverted patch / FIPS 204 §3.6.2 / `sign.ts`" thread, which had been
asserted in the FIPS 203 Stage 4 report but never verified. It is verified now, and the
earlier framing was correct.**

The operative verb is **`shall return false`** — not "shall reject", not "shall fail closed".
FIPS 204 makes the _manner_ of the response part of the requirement.

Behaviour was probed directly against the built `dist` rather than inferred from reading:

| Input                            | Result                         | §3.6.2 |
| -------------------------------- | ------------------------------ | ------ |
| pk length 1951 (one short)       | throws `PqcError(INVALID_KEY)` | ✗      |
| pk length 1953 (one long)        | throws `PqcError(INVALID_KEY)` | ✗      |
| pk length 0                      | throws `PqcError(INVALID_KEY)` | ✗      |
| pk length 1312 (an ML-DSA-44 pk) | throws `PqcError(INVALID_KEY)` | ✗      |
| pk length 2592 (an ML-DSA-87 pk) | throws `PqcError(INVALID_KEY)` | ✗      |
| σ length 3308 / 3310 / 0 / 2420  | returns `false`                | ✓      |
| both correct, genuine signature  | returns `true`                 | ✓      |

**The signature half conforms.** `sign.ts:73` calls the provider inside the try at
`sign.ts:71`, and `ml-dsa.js:590` does `if (sig.length !== sigCoder.bytesLen) return false;` —
commented upstream as "return false instead of exception". Guarded by
`sign.test.ts:90` (`returns false (never throws) for a malformed signature of the wrong
length`).

**The public-key half did not, as found.** `verify` called
`requireKey(publicKey, 'signer', 'public', 'verify')` **outside** the try block, and
`requireKey` (`algorithms.ts:120-125`) throws `PqcError('INVALID_KEY')` on a length mismatch.
The rejection never reached the catch that would have normalised it to `false`.

Scope: **SDK-scope and closable in this repository.** The defect was the position of one check
relative to a try block in a file this repository authors — not provider-internal, and not
covered by the vendoring constraint in §1.3. It was never grouped with F204-10 and F204-13.

**The correction, as applied (2026-09-08).** `sign.ts` gains
`hasWrongVerificationKeyLength(publicKey)`, called at the top of `verify`, which returns
`false` for exactly the condition §3.6.2 names and leaves everything else untouched:

```ts
if (hasWrongVerificationKeyLength(publicKey)) {
  return false;
}
const spec = requireKey(publicKey, 'signer', 'public', 'verify');
```

The scoping is the substance of the change, not incidental to it:

- The helper returns `true` **only** when the algorithm resolves to a registered signer spec,
  the use is `'public'`, and the byte length differs. Every other malformed-key condition —
  unknown algorithm, KEM key, secret key passed as public — falls through to `requireKey` and
  throws exactly as before.
- `requireKey` itself is **unmodified**. Throwing `INVALID_KEY` for a malformed key remains
  the convention across `encrypt`, `decrypt`, `sign` and the streaming entry points, where a
  bad key is an operator error with no meaningful "no" to return. `verify` is the one
  operation whose contract is a boolean, and the one the standard names.
- The algorithm lookup is widened to `Record<string, SignerSpec | undefined>` on purpose: a
  hand-built or deserialized key can carry any `algorithm` string at runtime, and an unknown
  algorithm is `requireKey`'s to report — not a length mismatch to swallow.

**Objective evidence.** `sign.test.ts`, two new cases, both passing:

| Test name                                                           | What it establishes                                                                                                                                                     |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `returns false (never throws) for a public key of the wrong length` | The pk half of §3.6.2, at five lengths: 0, 1951, 1953, 1312 (a valid ML-DSA-44 pk) and 2592 (a valid ML-DSA-87 pk)                                                      |
| `still throws for a malformed key that is not a length mismatch`    | The carve-out did not widen: wrong use still throws `WRONG_KEY_USE`, unknown algorithm still throws `UNSUPPORTED_ALGORITHM`, and a correct key still verifies to `true` |

The first mirrors the coverage `sign.test.ts:90` already had for signature length, including
the two lengths that are _valid_ for a different ML-DSA parameter set — the cases most likely
to arise from a real key-distribution mistake. The second is the guard that matters for
review: the obvious way to get this wrong is to relax `requireKey` globally, and that would
fail here immediately.

Behaviour re-probed against the rebuilt `dist` after the change: all five wrong pk lengths and
all four wrong σ lengths return `false`; a correct key with a genuine signature returns `true`.

Fail-closed behaviour was preserved throughout — a caller who ignored the thrown error never
obtained a `true`. The defect was one of prescribed manner, not of security posture, and the
correction changes the manner only.

Superseded by this correction: the earlier note that no test asserted this behaviour.
`sign.test.ts:111` (`rejects verify with a non-ML-DSA public key`) still asserts a _throw_,
correctly, for a different condition (wrong algorithm, which §3.6.2 does not govern), and
`sign-verify-catch.test.ts:31` still uses a **correct** 1952-byte key on purpose so it reaches
the signer.

### 3.5 F204-09 … F204-12 — Intermediate values

**F204-09 — CONFORMING (delegated).** `ml-dsa.js` contains 14 `cleanBytes` call sites, at
lines 372, 390, 411, 436, 466, 501, 538, 549, 554, 564, 570, 575, 659 and 684 — covering
keygen expansion, the signing loop's scratch state, `rnd` (`ml-dsa.js:466`, `:501`, wiping only
entropy the module itself generated), and the formatted message `M` in the external `sign`
wrapper. No breach was demonstrated. No test in this repository guards it, hence `(delegated)`.

**F204-10 — CONFORMING, closed 2026-09-08.** This is the row Stage 2 flagged as most likely
to be missed by analogy with FIPS 203, and the flag was warranted. FIPS 204 §3.6.3 extends the
destruction duty explicitly to verification, giving its reasons: signatures used as bearer
tokens, and signatures over plaintext intended to be confidential.

**The defect, as found.** `internal.verify` in the npm package (`ml-dsa.js:581-641`) contained
**zero** `cleanBytes` calls. Every one of the 14 sites in the file was in keygen, signing, or
the signing wrappers. The decoded `t1`, the recomputed `tr`, `mu`, `c2` and the reconstructed
commitment all survived the call.

**Why it became closable.** When first recorded this was provider-scope and not fixable from
here (§1.3). The ML-DSA surface has since been vendored into
`packages/core/src/vendor/ml-dsa/ml-dsa.ts`, and `algorithms.ts` resolves `ml-dsa-65` to that
copy, so a correction now ships to consumers through `dist`.

**The correction, as applied.** `internal.verify`'s body is wrapped in `try`/`finally`, and the
`finally` zeroizes every fresh intermediate: `t1`, `tr`, `mu`, `z`, `h`, `c`, `zNtt`, `c2` and
`wTick1`. The `finally` is what makes it complete — `verify` has seven early `return false`
exits, and zeroization on the success path alone would miss precisely the cases an attacker
drives.

Two things are deliberately **not** wiped, and both are load-bearing:

- `rho` and `cTilde`. `splitCoder.decode` returns subarray _views_ into its input for numeric
  segments and fresh objects only for coder segments, so `rho` aliases the caller's public key
  and `cTilde` the caller's signature. Wiping either destroys caller-owned memory.
- `mu` when `externalMu` is set, where it _is_ `msg` rather than a fresh digest. The
  implementation tracks this with an `ownMu` flag.

FIPS 204 §3.6.3 governs _intermediate_ data. FIPS 205 §3.1 is the standard that extends the
duty to "local copies of the inputs"; this is not that algorithm, and the scope is not widened
by analogy.

**Objective evidence.** `packages/core/src/vendor/ml-dsa/__tests__/verify-zeroization.test.ts`,
7 cases, all passing:

| Test name                                                                | What it establishes                                                                                                                            |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `still accepts a genuine signature`                                      | The change is output-inert on the success path                                                                                                 |
| `still rejects on each early-exit path without throwing`                 | Nine rejection routes, one per `return false`, all still return rather than throw                                                              |
| `leaves the public key byte-identical after verification`                | `rho` — a view into caller memory — was not wiped                                                                                              |
| `leaves the signature byte-identical after verification`                 | `cTilde` — likewise                                                                                                                            |
| `leaves the message byte-identical after verification`                   | `mu`'s alias to `msg` is respected                                                                                                             |
| `a key and signature stay reusable across repeated verifications`        | The end-to-end consequence: no caller-owned buffer is being consumed                                                                           |
| `verify wraps its body in try/finally and wipes the fresh intermediates` | Source-level: the `finally` exists, all nine intermediates are named, and `rho`/`cTilde`/`publicKey`/`sig` never appear in a `cleanBytes` call |

The three caller-memory tests are the ones that matter for review: the obvious way to get this
wrong is to wipe a decoded segment that turns out to be a view.

**One defect was introduced and removed during this work, recorded because the diff no longer
shows it.** A first attempt also wiped per-iteration scratch inside the verification loop —
`cleanBytes(ct12d, Az, wApprox)`. `polySub` mutates and returns `Az`, so `wApprox === Az`, and
`polyUseHint` operates in place on its argument, so the polynomial pushed into `wTick1` was
that same buffer. The wipe zeroed the reconstructed commitment and every genuine signature
failed to verify. Caught by the new tests, removed, and the aliasing is now documented at that
line so it is not re-added.

**Output is unchanged**, cross-verified against the unpatched npm primitive — see §3.6, which
records the same check for F204-13.

**Scope.** Closed for ML-DSA. SLH-DSA and X-Wing still resolve against the npm package and
remain provider-scope for this requirement.

**F204-11 — CONFORMING.** The seed carries its own `shall`: "shall be treated with the same
safeguards as a private key". `generateKeyPairFromSeed` (`keys.ts:60`) is absent from the
export block at `index.ts:22-34`, and `packages/core/package.json` declares a single `"."`
export with no subpath, so the seeded interface is unreachable from consumers. It is used only
by the test suite and the golden-vector scripts.

**F204-12 — NOT APPLICABLE.** Purely permissive: "does not require any special protections"
grants a permission and imposes no duty, so there is nothing to conform to. Same treatment as
F203-21 in the FIPS 203 matrix, which is the established precedent for a `MAY`-level row.

### 3.6 F204-13 — Floating-point arithmetic

The provider's ML-DSA rounding functions were read before this row was assigned a status —
the Stage 2 registry required that explicitly, and the first FIPS 203 matrix's retraction is
why. Four sites in `ml-dsa.js` use double division:

| Line  | Expression                                       | Function      |
| ----- | ------------------------------------------------ | ------------- |
| 174   | `Math.floor((rPlus - r0) / (2 * GAMMA2)) \| 0`   | `decompose`   |
| 215   | `Math.floor((rPlus - r0) / 2 ** D) \| 0`         | `Power2Round` |
| 201   | `Math.floor((Q - 1) / (2 * GAMMA2))`             | `HINT_M`      |
| 49-50 | `Math.floor((Q - 1) / 88) \| 0`, `.../ 32) \| 0` | `GAMMA2_1/2`  |

In JavaScript `/` is always IEEE-754 double division; wrapping it in `Math.floor` does not
change the arithmetic performed. `decompose` backs `HighBits` (`ml-dsa.js:177`) and `LowBits`
(`:178`) and runs per coefficient during both signing and verification; `Power2Round` runs
during key generation and signing.

FIPS 204 §3.6.4 is unconditional and is a `shall`. §3.6.4 even supplies the integer-only
construction — "ordinary integer division 𝑥/𝑦 computes ⌊𝑥/𝑦⌋, and ⌈𝑥/𝑦⌉ = ⌊(𝑥 + 𝑦 − 1)/𝑦⌋" —
which is not what the code does.

As with F203-19, the requirement is one of **method**, not of outcome: the ACVP vectors passed
throughout (`nist-vectors.test.ts:78`, `:87`) and no functional deviation was ever claimed.
Output correctness does not discharge a prohibition on the arithmetic medium.

**Why it became closable.** When first recorded this was provider-scope (§1.3). The ML-DSA
surface has since been vendored into `packages/core/src/vendor/ml-dsa/ml-dsa.ts`, and
`algorithms.ts` resolves `ml-dsa-65` to that copy.

**The correction, as applied.** All five sites are integer-only. The divisor decides the form,
following §3.6.4's own guidance — "If 𝑦 is a power of two, it may be more efficient to use bit
shift operations than integer division":

| Site          | Divisor                 | Replacement                                    |
| ------------- | ----------------------- | ---------------------------------------------- |
| `GAMMA2_1`    | 88 — not a power of 2   | `Number(BigInt(Q - 1) / 88n) \| 0`             |
| `GAMMA2_2`    | 32 — power of 2         | `((Q - 1) >>> 5) \| 0`                         |
| `decompose`   | 2·γ₂ — not a power of 2 | `Number(BigInt(rPlus - r0) / TWO_GAMMA2) \| 0` |
| `HINT_M`      | 2·γ₂ — not a power of 2 | `Number(BigInt(Q - 1) / TWO_GAMMA2)`           |
| `Power2Round` | 2¹³ — power of 2        | `((rPlus - r0) >>> D) \| 0`                    |

BigInt has no floating-point representation and its `/` truncates toward zero; the dividends
are exact multiples of their divisors, so truncation cannot round. `TWO_GAMMA2` is hoisted per
parameter set so the per-call cost is one BigInt allocation rather than two.

**Objective evidence.** `packages/core/src/vendor/ml-dsa/__tests__/rounding-equivalence.test.ts`,
7 cases, all passing. The domain is enumerated **exhaustively, not sampled** — both functions
reduce their input `mod q` first, so `rPlus` ranges over the whole of Z_q (q = 8 380 417):

| Check                                      | Evaluations                   | Result          |
| ------------------------------------------ | ----------------------------- | --------------- |
| `decompose`, γ₂ = (q−1)/88 (ML-DSA-44)     | 8 285 185                     | 0 discrepancies |
| `decompose`, γ₂ = (q−1)/32 (ML-DSA-65/87)  | 8 118 529                     | 0 discrepancies |
| `Power2Round`                              | 8 380 417 — all of Z_q        | 0 discrepancies |
| `GAMMA2_1`, `GAMMA2_2`, `HINT_M` (both γ₂) | constants, pinned to literals | exact           |

Two supporting cases guard the preconditions rather than the outputs: that the dividend is
always an exact non-negative multiple of 2·γ₂, and that the `>>>` operand stays within
`[0, 2³¹)` — `>>>` coerces through ToUint32 and would wrap silently rather than fail. A final
case asserts on the **source text**, because no behavioural test can detect a regression here:
the original expressions were bit-exact too, and reintroducing `Math.floor(x / y)` would pass
every output check while re-opening the finding.

**Cross-compatibility: the correction changed method, not output.** Verified directly against
the unpatched npm primitive, which is the check that matters for a vendoring — existing
signatures and keys must stay valid:

| Direction                                     | Result |
| --------------------------------------------- | ------ |
| vendored `pqc.sign` → npm `ml_dsa65.verify`   | `true` |
| npm `ml_dsa65.sign` → vendored `pqc.verify`   | `true` |
| npm `keygen` + `sign` → vendored `pqc.verify` | `true` |

**Performance note, recorded rather than buried.** BigInt division in `decompose` measured
≈4.2× the cost of the float expression in isolation (138 ms → 585 ms over 5 M iterations), and
`decompose` runs per coefficient during both signing and verification. `Power2Round` and
`GAMMA2_2` use shifts and are not affected. This is the same trade-off accepted for ML-KEM's
`Compress_d` (F203-19) and is a known cost of conformance here, not an oversight.

**Scope.** Closed for ML-DSA. SLH-DSA still resolves against the npm package; its equivalent
question is registered but unexamined — `FIPS-205-MATRIX.md` §3.4 records that neither this
finding nor the ML-KEM one transfers to it.

### 3.7 F204-14, F204-15 — Hedged and deterministic signing

**F204-14 — NOT APPLICABLE. The deterministic variant is definitively unreachable through any
public path**, and this was settled rather than hedged:

1. `SignatureOptions` (`types.ts:38-41`) declares `context` only.
2. `toNobleOptions` (`sign.ts:14-25`) does not forward its argument. It **constructs a new
   object**, returning either `undefined` or `{ context: options.context }`. Any additional
   property on a caller-supplied object — including `extraEntropy` passed from untyped
   JavaScript, which TypeScript could not prevent — is discarded before the provider is
   reached.
3. `sign.ts:45` passes that constructed object as the only options argument.
4. `SIGNATURE_ALGORITHMS` is not exported from `index.ts`, and the package declares a single
   `"."` export, so the provider object cannot be reached directly to call it with
   `extraEntropy: false`.

Point 2 is the decisive one: even a caller who bypasses the type system cannot deliver
`extraEntropy` to the provider. The deterministic variant is a construct this SDK does not
expose.

**F204-15 — CONFORMING.** §3.4 states that hedged-only "is sufficient to guarantee
interoperability", and that "the same verification algorithm will work to verify signatures
produced by either variant". The SDK implements hedged-only. Interoperability with externally
produced signatures is evidenced by the ACVP sigVer vectors at `nist-vectors.test.ts:87`,
which verify signatures this SDK did not generate.

### 3.8 F204-16 — Context string

**CONFORMING.** `sign.ts:6` sets `MAX_CONTEXT_LENGTH = 255`, citing FIPS 204 §5.2.
`toNobleOptions` (`sign.ts:18-23`) throws `PqcError('INVALID_CONTEXT')` above that length, and
`sign.ts:70` deliberately calls it **outside** the try in `verify` — the inverse of the
F204-08 defect, and correct here, since an oversized context is a caller error rather than a
signature that should verify to `false`. The comment at `sign.ts:68-69` records that intent.

Guarded by two tests: `sign.test.ts:69` (`accepts a context of exactly 255 bytes (the FIPS 204
maximum)`) pins the boundary as inclusive, and `sign.test.ts:78` (`rejects an oversized context
with INVALID_CONTEXT from both sign and verify`) covers both entry points.

The 255-byte cap is also stated in the Algorithm 2 input declaration and in §5.4 for
HashML-DSA; the latter is inert here (§3.9).

### 3.9 F204-17 … F204-20 — Pre-Hash ML-DSA (HashML-DSA)

**Confirmed as flagged in Stage 2: the SDK does not expose HashML-DSA.** All four rows are
`NOT APPLICABLE`.

- The provider implements it — `ml-dsa.d.ts:27` declares
  `prehash: (hash: TArg<CHash>) => TRet<Signer>`, with the implementation at `ml-dsa.js:666`.
- A repository-wide grep over `packages/core/src` and `packages/cli/src` finds **no** reference
  to `prehash` outside `packages/core/src/vendor/ml-kem/utils.ts`, which is the whole-file
  vendored copy of the provider's shared utilities. Those symbols are dead code there: the
  vendored `utils.ts` is imported only by the vendored ML-KEM module, and ML-DSA resolves to
  the npm package's own copy.
- `sign.ts:45` calls `spec.signer.sign(...)` — the pure variant only.
- `SIGNATURE_ALGORITHMS` is not exported from `index.ts:22-34`, so a consumer cannot reach the
  provider object to call `prehash()` through this package's public entry point.

The rows are retained rather than deleted so the coverage boundary stays visible. If
HashML-DSA is ever exposed, §5.4 brings its own Algorithms 4–5 and all four activate together
— including F204-18, whose FIPS 140 validation clause no change to this library could satisfy
on its own.

### 3.10 F204-21, F204-22 — Symmetric primitives and key binding

**F204-21 — CONFORMING (delegated).** `ml-dsa.js` imports `shake128` and `shake256` from
`@noble/hashes/sha3.js`, the FIPS 202 functions, and uses them byte-oriented with `dkLen`
expressed in bytes throughout. No test in this repository isolates the hash wiring; the ACVP
vectors exercise it indirectly, which is assurance evidence rather than a direct guard.

**F204-22 — NOT APPLICABLE.** §3.5's `should` is addressed to "users of digital signatures",
not to the implementation, and concerns binding a public key to an identity — certificates,
proof of possession, PKI. `packages/core/src` implements no identity, certificate or binding
surface of any kind; it handles raw keys and signatures. The requirement addresses a construct
this SDK does not implement or expose.

---

## 4. Summary

Conformity pass, 2026-09-08, updated by the corrective passes that closed F204-08, F204-10
and F204-13, and by the 2026-09-09 pass that closed F204-01 and activated F204-04. All 22
rows determined; none remain `NOT EVALUATED`.

| Status                                            | Count  | Req IDs                                                                |
| ------------------------------------------------- | ------ | ---------------------------------------------------------------------- |
| CONFORMING                                        | 8      | F204-01, F204-05, F204-08, F204-10, F204-11, F204-13, F204-15, F204-16 |
| CONFORMING (delegated)                            | 4      | F204-06, F204-07, F204-09, F204-21                                     |
| PARTIALLY CONFORMING                              | 0      | —                                                                      |
| NONCONFORMING                                     | 0      | —                                                                      |
| NONCONFORMING (provider-scope, not closable here) | 0      | —                                                                      |
| INDETERMINATE                                     | 3      | F204-02, F204-03, F204-04                                              |
| NOT EVALUATED                                     | 0      | —                                                                      |
| NOT APPLICABLE                                    | 7      | F204-12, F204-14, F204-17, F204-18, F204-19, F204-20, F204-22          |
| **Total**                                         | **22** |                                                                        |

### 4.1 Aggregate-score caution

These counts are an inventory, not a score. They must not be reduced to a percentage or a
pass mark. The rows are not of equal weight, they do not share a single duty-holder, and they
are not equally closable:

- **All three nonconformities are now closed** — F204-08 in `sign.ts` (§3.4), and F204-10 and
  F204-13 by vendoring the ML-DSA primitive (§3.5, §3.6). The last two were recorded as
  provider-scope and not closable; that changed because the SDK stopped resolving ML-DSA to
  the npm package, not because the requirements softened.
- **Vendoring is a maintenance liability, not a free win.** ML-DSA is now forked at 0.7.1
  alongside ML-KEM: every upstream release must be re-vendored and re-verified rather than
  picked up by a version bump. Accepted here only because two `shall` statements could not
  otherwise be satisfied for consumers.
- **F204-10 and F204-13 are provider-scope.** They are demonstrably not satisfied, and no
  change to `packages/core/src` can close them for consumers, because `dist` imports
  `@noble/post-quantum` as an external runtime import. Closing them would require vendoring
  `ml-dsa.ts` as was done for ML-KEM — a decision this document does not make.
- **The 7 `NOT APPLICABLE` rows are the largest single group, and that is a statement about
  surface area, not about quality.** Four are HashML-DSA, one is the deterministic variant,
  two cover symmetric-primitive/key-binding constructs — all constructs the SDK does not
  expose. A larger surface would convert them into rows requiring evidence. (ML-DSA-44 left
  this group on 2026-09-09, when it stopped being one of those unexposed constructs — see
  F204-04 below.)
- **F204-01 closed 2026-09-09** by exposing all three parameter sets with per-set ACVP
  round-trip evidence (§3.1). Availability in the provider was never the gate — the row
  moved on registration plus evidence, exactly as its own opening rule required.
- **F204-02, F204-03 and F204-04 cannot be settled here at all**, and are the requirements
  most likely to matter to a downstream compliance reviewer. F204-04 joined this group on
  2026-09-09, the moment ML-DSA-44 became reachable — it did not inherit `INDETERMINATE`
  by default; the same host-RBG-visibility reasoning as F204-02/03 was re-derived and written
  out explicitly for it (§3.1).
- **Four rows carry `(delegated)`**, meaning their evidence is source inspection of a
  dependency rather than a test in this repository. A provider version bump could change any
  of them silently.

### 4.2 Validation status

**No claim of FIPS validation is made or implied by this document.** Nothing in this
repository has been submitted to, or evaluated under, the NIST Cryptographic Module Validation
Program or the Cryptographic Algorithm Validation Program. This matrix records the result of a
**self-assessment** by static analysis and targeted runtime probes. Conformance,
validation-readiness, and official validation status are three separate things, and only the
first is addressed here.

ACVP known-answer vectors (`packages/core/src/vectors/mldsa{44,65,87}-keygen.json` and
`mldsa{44,65,87}-sigver.json`, all six exercised by the `ML_DSA_SETS`-parametrized blocks in
`nist-vectors.test.ts`, added 2026-09-09 for the `-44`/`-87` pair) are assurance evidence.
They demonstrate input/output agreement with the standard on the tested paths.
**They are not automatic proof of every internal normative condition** — F204-13 is the
standing counterexample here, exactly as F203-19 is in the FIPS 203 matrix: the vectors pass
while the requirement is breached, because a known-answer test cannot observe _how_ a result
was computed.

### 4.3 Next actions (not performed in this pass)

1. ~~**F204-08**, ~~**F204-10**, ~~**F204-13**~~~~ — closed 2026-09-08 (§3.4, §3.5, §3.6). No
   further action.
2. **F204-06, F204-07** — map RBG failure in `keys.ts` and `sign.ts` to
   `PqcError('RBG_FAILURE')`, for consistency with the ML-KEM path and with
   `.claude/rules/crypto-review.md`. Not a FIPS 204 breach (§3.3); a repo-rule and
   consistency fix.
3. **F204-05** — add a test asserting two signatures over the same message differ, evidencing
   that signing is hedged.
4. **F204-09, F204-21** — convert two `(delegated)` rows into evidenced ones, installing a
   tripwire against provider drift.
5. **Re-vendoring discipline** — `ml-dsa.ts` now carries local corrections. On any
   `@noble/post-quantum` bump, re-copy and re-apply rather than hand-merge, per
   `packages/core/src/vendor/ml-kem/NOTICE.md`. The equivalence and zeroization suites are
   the tripwire; do not adjust them to match new output.
6. ~~**F204-01** — expose ML-DSA-44 and ML-DSA-87~~ — closed 2026-09-09 (§3.1). No further
   action; F204-04 activated as its direct consequence and was determined in the same pass.

### 4.4 Change log

| Date       | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-09-08 | Registry pass (Phase 1, Stage 2). 22 rows registered from FIPS 204; 18 NOT EVALUATED, 4 NOT APPLICABLE. No code read for conformity, no code changed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 2026-09-08 | Conformity pass (Phase 2). All 22 rows determined against `packages/core/src` with file/line and test citations. F204-08 NONCONFORMING (SDK-scope); F204-10 and F204-13 NONCONFORMING (provider-scope). The §3.6.2 / `sign.ts` thread carried over from the FIPS 203 Stage 4 report is verified and resolved in §3.4. No code changed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 2026-09-08 | Corrective pass. ML-DSA surface vendored into `packages/core/src/vendor/ml-dsa/` and wired through `algorithms.ts`. F204-13 closed (integer-only Decompose/Power2Round/HINT_M/GAMMA2, exhaustively verified over Z_q) and F204-10 closed (try/finally zeroization in `internal.verify`). Output cross-verified against the unpatched npm primitive in both directions. NONCONFORMING count now 0 in every scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2026-09-08 | Corrective pass. F204-08 closed: `verify` returns `false` for a wrong-length public key via `hasWrongVerificationKeyLength` in `sign.ts`, scoped so that every other malformed-key condition still throws through an unmodified `requireKey`. Two regression tests added to `sign.test.ts`. NONCONFORMING count now 0 SDK-scope, 2 provider-scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 2026-09-09 | Corrective pass. F204-01 closed: `SignerSpec.signer` refactored from `typeof ml_dsa65` to the structural `NobleSigner` interface (mirroring `NobleKem`); `SignatureAlgorithm` widened to `'ml-dsa-44' \| 'ml-dsa-65' \| 'ml-dsa-87'`; both registered with byte lengths read from the provider at runtime. Confirmed F204-13/F204-10 apply to all three sets by reading `getDilithium`'s shared factory body, not by inference. Six new ACVP vector files added (same NIST ACVP-Server provenance as the existing `mldsa65-*.json` pair), wired into `nist-vectors.test.ts` as a parametrized loop; 20/16/20 keyGen+sigVer cases pass for -44/-65/-87 respectively. F204-04 activated as a direct consequence and determined **INDETERMINATE**, explicitly, for the same host-RBG-visibility reason as F204-02/F204-03 — not inherited silently. F204-03's applicability text corrected to reflect ML-DSA-87 now being registered (§3.2); its determination is unchanged. `SUPPORTED_ALGORITHMS`, `sign`/`verify` (now generic over `SignatureAlgorithm`), the CLI's `keygen --algorithm` help text, and `docs/serialization-format.md`'s key-length table updated to match. |
