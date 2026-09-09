# FIPS 205 (SLH-DSA) — Conformance Matrix

**Object of assessment:** `@pqc-sdk/core` @ `0.8.3`, commit `3d76be9`, branch `main`
**Normative document:** FIPS 205, _Stateless Hash-Based Digital Signature Standard_
(NIST, 13 August 2024)
**Primitive provider:** `@noble/post-quantum@0.7.1` (exact pin) — exports all 12 parameter
sets; the SDK registers **none** (see §1.3)
**Assessment date:** 2026-09-08 (registry pass — Phase 1)
**Method:** normative registry only. Requirements were extracted from the standard and
mapped to the code surface that would govern them. **No conformity determination was made.**
Every row is `NOT APPLICABLE` because SLH-DSA is not implemented by this SDK — an
_applicability_ finding, verified against the code, not a conformity one.

---

## 1. Scope and reading instructions

This matrix registers the normative content of FIPS 205 that would bear on an SLH-DSA
surface in `packages/core`. It is the FIPS 205 counterpart of
`docs/compliance/FIPS-203-MATRIX.md` and `FIPS-204-MATRIX.md`, and uses the same eight
columns, the same status vocabulary, and the same evidence discipline. Row identifiers use
the `F205-` prefix.

> **Read this before the table.** Unlike the ML-KEM and ML-DSA matrices, **no row here has a
> conformity state, because there is no SLH-DSA implementation to assess.** The requirements
> are registered so that the coverage boundary is explicit and so that adding SLH-DSA starts
> from a complete list rather than from scratch. Nothing in this document should be read as
> a claim about SLH-DSA support, in either direction.

Quotations are copied verbatim from the standard. Where a requirement is too long to quote
whole, the operative fragment — the `shall`/`should` and its immediate context — is quoted
and the remainder referenced by section number. No requirement is paraphrased into the
Quote column.

### 1.1 Keyword semantics

FIPS 205 §2.1 defines `shall` and `should` identically to FIPS 203 and FIPS 204:

> `shall` — Used to indicate a requirement of this standard.
> `should` — Used to indicate a strong recommendation but not a requirement of this
> standard. Ignoring the recommendation could lead to undesirable results.

`must` is **not** defined by FIPS 205, yet appears in normative-sounding positions — §3.2
("Care must be taken to protect implementations against attacks") and §10.2 ("the hash or
XOF of the content to be signed must be computed within a FIPS 140-validated cryptographic
module"). Statements resting solely on an undefined `must` carry `MUST (undefined)` in the
_Normative Force_ column and are **not** treated as discharged or as breached. Same Class M
treatment as the other two matrices.

### 1.2 Status vocabulary

Identical to `FIPS-204-MATRIX.md` §1.2:

| Status                     | Meaning                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **CONFORMING**             | Requirement is applicable, satisfied, and supported by objective evidence in this repository.                                   |
| **CONFORMING (delegated)** | Requirement is satisfied by the pinned provider, verified by source inspection, but not guarded by any test in this repository. |
| **PARTIALLY CONFORMING**   | Satisfied for part of the declared scope only.                                                                                  |
| **NONCONFORMING**          | Applicable requirement demonstrably not satisfied.                                                                              |
| **INDETERMINATE**          | Applicability or satisfaction cannot be settled from the evidence available in this pass.                                       |
| **NOT EVALUATED**          | Applicable, but no determination has been attempted yet.                                                                        |
| **NOT APPLICABLE**         | Requirement addresses a construct this SDK does not implement or expose.                                                        |

Every row here is `NOT APPLICABLE`, on the last definition. This is the same treatment given
to the HashML-DSA rows in `FIPS-204-MATRIX.md` §3.9, applied to an entire algorithm rather
than one variant of one.

`NOT APPLICABLE` here means "there is nothing to conform to yet", **not** "this requirement
does not matter". Each row activates the moment SLH-DSA is registered.

### 1.3 Boundary of responsibility — SLH-DSA is not implemented

Verified against the code, not assumed:

| Surface                                    | State                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| `SignatureAlgorithm` (`types.ts:10`)       | `'ml-dsa-65'` only — no SLH-DSA member                                   |
| `SIGNATURE_ALGORITHMS` (`algorithms.ts`)   | one entry, `ml-dsa-65`                                                   |
| `SUPPORTED_ALGORITHMS` (`index.ts:63`)     | `['ml-kem-768', 'ml-dsa-65', 'x-wing']`                                  |
| Import of `@noble/post-quantum/slh-dsa.js` | **none** anywhere in `packages/core/src` or `packages/cli/src`           |
| Any `slh` / `sphincs` identifier           | **none**; the sole textual match is a prose comment at `algorithms.ts:8` |

This matches the project's own statement in `CLAUDE.md`: "Algorithms (roadmap, not yet
implemented): SLH-DSA (FIPS 205)."

**The provider, by contrast, implements SLH-DSA completely** — all 12 parameter sets of
Table 2, plus `.prehash()` on each (§3.9). That asymmetry is the single most important fact
in this document, and it cuts the way the other matrices already record: **availability in
the provider is availability only, never conformance.** Registering a parameter set would
require its own row-by-row determination against this matrix, exactly as
`FIPS-204-MATRIX.md` §3.1 requires for ML-DSA-44 and ML-DSA-87.

Were SLH-DSA registered today it would be **Provider-scope**, like ML-DSA and unlike ML-KEM:
`dist` imports `@noble/post-quantum` as an external runtime import, so consumers execute
their own registry-resolved copy and no patch in this repository reaches it. Only the ML-KEM
surface was vendored (`packages/core/src/vendor/ml-kem/`).

### 1.4 Structural differences from FIPS 203 and FIPS 204

Registered so a later phase does not force a mapping onto the other two matrices:

| Area                            | FIPS 203              | FIPS 204                     | FIPS 205                                                            |
| ------------------------------- | --------------------- | ---------------------------- | ------------------------------------------------------------------- |
| Additional-requirements section | §3.3                  | §3.6 (4 subsections)         | **§3.1**, with §3.2 as explicitly non-normative considerations      |
| Random values per keygen        | one seed              | one seed 𝜉                   | **three**: SK.seed, SK.prf, PK.seed (F205-01)                       |
| RBG strength                    | fixed per param set   | fixed, plus a dual threshold | **parametric: 8𝑛 bits**, 𝑛 ∈ {16, 24, 32} (F205-02)                 |
| Destruction duty                | intermediates         | + verification intermediates | + **"local copies of the inputs"** (F205-03)                        |
| Key checks                      | §7.2/§7.3 input check | `shall return false`         | **SP 800-89 assurance**: 2𝑛-byte pk, 4𝑛-byte sk + PK.root recompute |
| Component reuse                 | K-PKE `shall not`     | —                            | WOTS+/XMSS/FORS/hypertree **`should not`** be exposed (F205-08)     |
| Verify context check            | —                     | not separately stated        | Alg. 24/25 **`return false`**, vs `⊥` in Alg. 22/23 (F205-13/14)    |
| Parameter sets                  | 3                     | 3                            | **12** (SHA2/SHAKE × 128/192/256 × s/f)                             |

---

## 2. Compliance matrix

| Req ID      | FIPS 205 Quote                                                                                                                                                                                                                               | Section               | Normative Force      | Applicability                                                | SDK Component                                                            | Evidence Required                                                                                        | Current Status                 |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ------------------------------ |
| **F205-01** | "For each invocation of key generation, each of these values shall be a fresh (i.e., not previously used) random value generated using an approved random bit generator (RBG), as prescribed in SP 800-90A, SP 800-90B, and SP 800-90C"      | §3.1                  | SHALL                | Not applicable — no SLH-DSA key generation exists            | Would be `keys.ts` (`generate`) + provider `keygen`                      | Three fresh values per invocation (SK.seed, SK.prf, PK.seed), from an RBG validated under SP 800-90A/B/C | **NOT APPLICABLE** — see §3.1  |
| **F205-02** | "Moreover, the RBG used shall have a security strength of at least 8𝑛 bits."                                                                                                                                                                 | §3.1                  | SHALL                | Not applicable — no parameter set registered, so no 𝑛        | Host RBG — outside repository control                                    | Documented host security strength ≥ 128/192/256 bits for 𝑛 = 16/24/32                                    | **NOT APPLICABLE** — see §3.1  |
| **F205-03** | "implementations of SLH-DSA shall ensure that any local copies of the inputs and any potentially sensitive intermediate data are destroyed as soon as they are no longer needed."                                                            | §3.1                  | SHALL                | Not applicable — no SLH-DSA code path                        | Would be provider internals + SDK-held inputs                            | Zeroization on keygen, signing **and verification**, covering local copies of message/signature/pk       | **NOT APPLICABLE** — see §3.2  |
| **F205-04** | "In the case of SLH-DSA, where public-key validation is required, implementations shall verify that the public key is 2𝑛 bytes in length."                                                                                                   | §3.1                  | SHALL                | Not applicable — no SLH-DSA key type                         | Would be `algorithms.ts` (`requireKey`)                                  | Public key length checked as exactly 2𝑛 bytes for the parameter set                                      | **NOT APPLICABLE** — see §3.3  |
| **F205-05** | "the owner of the private key shall check that the private key is 4𝑛 bytes in length and shall use SK.seed and PK.seed to recompute PK.root and compare the newly generated value with the value in the private key"                         | §3.1                  | SHALL                | Not applicable — no private-key-possession assurance surface | Would be a new `keys.ts` entry point                                     | A regeneration check: 4𝑛-byte length, PK.root recomputed and compared                                    | **NOT APPLICABLE** — see §3.3  |
| **F205-06** | "Implementations of SLH-DSA shall not use floating-point arithmetic, as rounding errors in floating point operations may lead to incorrect results in some cases."                                                                           | §3.1                  | SHALL                | Not applicable — no SLH-DSA code path                        | Would be provider `slh-dsa.js`                                           | Integer-only implementation throughout, including `gen_len2` (Algorithm 1)                               | **NOT APPLICABLE** — see §3.4  |
| **F205-07** | "it is recommended that this value be precomputed. For all parameter sets in this standard, 𝑙𝑒𝑛2 is 3."                                                                                                                                      | §3.1                  | Recommendation       | Not applicable — no SLH-DSA code path                        | Would be provider `slh-dsa.js`                                           | `len2` precomputed rather than derived at runtime by Algorithm 1                                         | **NOT APPLICABLE** — see §3.4  |
| **F205-08** | "As WOTS+, XMSS, FORS, and hypertree signature schemes are not approved for use as stand-alone signature schemes, cryptographic modules should not make interfaces to these components available to applications."                           | §3.2                  | SHOULD NOT           | Not applicable — no SLH-DSA surface, component or otherwise  | Would be `index.ts` export map                                           | No WOTS+/XMSS/FORS/hypertree entry point reachable from `@pqc-sdk/core`                                  | **NOT APPLICABLE** — see §3.5  |
| **F205-09** | "Care must be taken to protect implementations against attacks, such as side-channel attacks or fault attacks"                                                                                                                               | §3.2                  | MUST (undefined)     | Not applicable — no SLH-DSA code path                        | Would be provider internals                                              | Interpretation of the undefined keyword is open; §3.2 is explicitly non-normative                        | **NOT APPLICABLE** — see §3.5  |
| **F205-10** | "Other than for testing purposes, the interfaces for key generation and signature generation specified in this section should not be made available to applications, as any random values … shall be generated by the cryptographic module." | §9 (preamble)         | SHOULD NOT + SHALL   | Not applicable — no SLH-DSA surface                          | Would be `index.ts` export map; cf. `keys.ts:60` for the ML-DSA analogue | Derandomized `slh_keygen_internal` / `slh_sign_internal` absent from the package export map              | **NOT APPLICABLE** — see §3.6  |
| **F205-11** | "4: if SK.seed = NULL or SK.prf = NULL or PK.seed = NULL then / 5: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                                    | §10.1, Alg. 21        | Definitional         | Not applicable — no SLH-DSA key generation                   | Would be `keys.ts` (`generate`)                                          | RBG failure during key generation produces an error indication and yields no key                         | **NOT APPLICABLE** — see §3.7  |
| **F205-12** | "5: if 𝑎𝑑𝑑𝑟𝑛𝑑 = NULL then / 6: return ⊥ ▷ return an error indication if random bit generation failed"                                                                                                                                        | §10.2, Alg. 22 & 23   | Definitional         | Not applicable — no SLH-DSA signing                          | Would be `sign.ts` (`sign`)                                              | RBG failure during signing produces an error indication and yields no signature                          | **NOT APPLICABLE** — see §3.7  |
| **F205-13** | "1: if \|𝑐𝑡𝑥\| > 255 then / 2: return ⊥ ▷ return an error indication if the context string is too long"                                                                                                                                      | §10.2, Alg. 22 & 23   | Definitional         | Not applicable — no SLH-DSA signing                          | Would be `sign.ts:6` (`MAX_CONTEXT_LENGTH`), currently ML-DSA-only       | Contexts over 255 bytes refused on signing with a documented `PqcError`                                  | **NOT APPLICABLE** — see §3.8  |
| **F205-14** | "1: if \|𝑐𝑡𝑥\| > 255 then / 2: return false"                                                                                                                                                                                                 | §10.3, Alg. 24 & 25   | Definitional         | Not applicable — no SLH-DSA verification                     | Would be `sign.ts` (`verify`)                                            | Oversized context on **verify** returns `false`, not an error — asymmetric with Alg. 22/23               | **NOT APPLICABLE** — see §3.8  |
| **F205-15** | "If the default hedged variant of slh_sign_internal is used, the 𝑛-byte random value 𝑎𝑑𝑑𝑟𝑛𝑑 shall be generated by the cryptographic module that runs slh_sign_internal."                                                                     | §10.2                 | SHALL                | Not applicable — no SLH-DSA signing                          | Would be `sign.ts` + provider `sign`                                     | `addrnd` sampled inside the module, never accepted from callers on a production path                     | **NOT APPLICABLE** — see §3.9  |
| **F205-16** | "In the case of hash_slh_sign, the hash or XOF of the content to be signed must be computed within a FIPS 140-validated cryptographic module"                                                                                                | §10.2                 | MUST (undefined)     | Not applicable — no HashSLH-DSA surface                      | Provider `.prehash()` — present, unreferenced by this SDK                | —                                                                                                        | **NOT APPLICABLE** — see §3.9  |
| **F205-17** | "the digest that is signed needs to be generated using an approved hash function or XOF … that provides at least 8𝑛 bits of classical security strength against both collision and second preimage attacks"                                  | §10.2                 | Undefined ("needs")  | Not applicable — no HashSLH-DSA surface                      | Provider `.prehash(hash)` — caller-selected hash                         | —                                                                                                        | **NOT APPLICABLE** — see §3.9  |
| **F205-18** | "a single key pair may be used for both pure and pre-hash signatures, it is recommended that each key pair only be used for one version or the other."                                                                                       | §10.2                 | MAY + Recommendation | Not applicable — no SLH-DSA key type                         | Would be `keys.ts` (`generate`)                                          | —                                                                                                        | **NOT APPLICABLE** — see §3.9  |
| **F205-19** | "In general, the pure version is preferred."                                                                                                                                                                                                 | §10.2                 | Recommendation       | Not applicable — neither variant exposed                     | Would be `sign.ts`                                                       | If both variants are offered, the pure one is the default                                                | **NOT APPLICABLE** — see §3.9  |
| **F205-20** | "2: 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛𝑑 ▷ substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant" + "skip lines 4 through 7 for the deterministic variant"                                                                                                | §9.2 Alg. 19; Alg. 22 | Definitional         | Not applicable — neither variant exposed                     | Would be `types.ts` (`SignatureOptions`) + `sign.ts`                     | Which variant(s) the public API can reach, and whether a caller can select the deterministic one         | **NOT APPLICABLE** — see §3.10 |
| **F205-21** | "The 12 parameter sets included in Table 2 were designed to meet certain security strength categories defined by NIST in its original Call for Proposals"                                                                                    | §11, Table 2          | Definitional         | Project scope declares SLH-DSA; 0 of 12 registered           | `types.ts:10`, `algorithms.ts` (`SIGNATURE_ALGORITHMS`)                  | Registry entry, exported type member, Table 2 pk/sig byte lengths, ACVP round-trip per set               | **NOT APPLICABLE** — see §3.11 |

---

## 3. Registry notes

These notes record what was **read from the standard** and what the code surface **is**. They
contain no conformity determinations.

### 3.1 F205-01, F205-02 — Randomness generation

Structurally different from both other standards, in two ways worth keeping separate.

**Three values, not one.** ML-KEM draws one 32-byte `m` per encapsulation; ML-DSA draws one
32-byte seed 𝜉 per keygen. SLH-DSA keygen draws **three** 𝑛-byte values — PK.seed, SK.seed
and SK.prf — and the `shall` on freshness and approval attaches to each of them individually
("each of these values shall be a fresh … random value").

**The strength threshold is parametric.** FIPS 203 and FIPS 204 state fixed bit counts per
parameter set. FIPS 205 states "at least 8𝑛 bits", with 𝑛 ∈ {16, 24, 32} per Table 2 — that
is, 128, 192 or 256 bits. A row for this requirement cannot be written without first fixing
which parameter sets are registered.

Both rows would be `INDETERMINATE` rather than `CONFORMING` were SLH-DSA implemented, for
the same reason F203-12 and F204-02 are: the requirement constrains the _source_ of the
randomness, which is a property of the host runtime and not visible to this assessment.
`SECURITY.md` § "Randomness source" documents the per-runtime picture.

### 3.2 F205-03 — Destruction of sensitive data

**Broader than the FIPS 204 equivalent, which is itself broader than FIPS 203's.** The
progression is worth recording because it is easy to flatten:

- FIPS 203 §3.3 — intermediates of KeyGen/Encaps/Decaps.
- FIPS 204 §3.6.3 — the same, **plus** verification-side intermediates.
- FIPS 205 §3.1 — the same, **plus** "any local copies of **the inputs**".

That last clause reaches further than intermediates: the message, the signature and the
public key held by the caller-facing layer are themselves in scope on the verification path.
FIPS 205 gives the same rationale as FIPS 204 — bearer-token signatures, signatures over
confidential plaintext.

Note for a later phase: `FIPS-204-MATRIX.md` §3.5 records F204-10 as **NONCONFORMING
(provider-scope)** because `internal.verify` in `ml-dsa.js` contains zero `cleanBytes` calls.
The corresponding question for `slh-dsa.js` has **not** been asked here and must not be
assumed to have the same answer.

### 3.3 F205-04, F205-05 — Key checks

These derive from SP 800-89 rather than from the algorithm specification, and have no
counterpart in the other two matrices.

F205-04 (public key is 2𝑛 bytes) is the closest FIPS 205 analogue to FIPS 204 §3.6.2 — but
note it is **not** the same requirement. FIPS 204 prescribes the _manner_ of the response
("shall return false"); FIPS 205 §3.1 says only that the implementation "shall verify" the
length, leaving the response unspecified. A later phase must not import the `return false`
reading from F204-08 onto this row without re-reading §3.1.

F205-05 is an obligation on the **key owner**, not on the verifier, and it is conditional
("When the assurance of private key possession is obtained via regeneration"). It requires
two things: a 4𝑛-byte length check, and recomputing PK.root from SK.seed and PK.seed and
comparing it to the stored value. Nothing in the SDK offers a private-key-possession
assurance surface today.

### 3.4 F205-06, F205-07 — Floating-point arithmetic

F205-06 is textually near-identical to FIPS 203 §3.3 and FIPS 204 §3.6.4, and §3.1 supplies
the same integer-only construction: "ordinary integer division 𝑥/𝑦 computes ⌊𝑥/𝑦⌋, and
⌈𝑥/𝑦⌉ = ⌊(𝑥 + 𝑦 − 1)/𝑦⌋".

⚠️ Two cautions carried forward, both of which cost a retraction or a correction in the
earlier matrices:

1. **Grepping for `Math.` is not a test for this requirement.** In JavaScript `/` alone is
   double division. The ML-KEM defect (F203-19) was `((i << d) + Q / 2) / Q`, containing no
   `Math.` call; the ML-DSA finding (F204-13) was `Math.floor(x / y)`, where the `Math.floor`
   is not what makes it floating-point.
2. **Do not declare a finding before reading the provider's code.** `slh-dsa.js` has not
   been examined for this pass, and this document records no view on whether it complies.

F205-07 is the only _recommendation_ in §3.1 and is registered separately because it is
adjacent to F205-06 but carries no requirement force: `len2` may be computed by Algorithm 1
without floating point, and the standard merely recommends precomputing it, noting the value
is 3 for every parameter set.

### 3.5 F205-08, F205-09 — §3.2 implementation considerations

**§3.2 is explicitly non-normative.** §3.1 opens by saying so: "Section 3.2 discusses issues
that implementers of cryptographic modules should take into consideration but that are not
requirements." Both rows are registered with that framing rather than as obligations.

F205-08 is nonetheless the closest FIPS 205 has to FIPS 203's K-PKE clause, with a weaker
force: FIPS 203 §3.3 says K-PKE "shall not be used as a stand-alone cryptographic scheme",
whereas FIPS 205 §3.2 says modules "should not make interfaces to these components available
to applications". A `should not` in a section the standard states is not a requirement.

F205-09 rests on an undefined `must` and is recorded Class M (§1.1).

### 3.6 F205-10 — Internal interfaces

> **Discrepancy from the work order.** The instruction placed this statement in the "§10
> preamble". It is in the **§9 preamble** (immediately before §9.1, under "9 SLH-DSA Internal
> Functions"). The §10 preamble says something different and non-normative: "This section
> provides guidance on the key generation, signature generation, and signature verification
> functions that should be provided for use by applications."
>
> The substance of the instruction was right: §9 does carry both a `should not` and a
> `shall`, quoted verbatim in the row. Only the section number differs, and it is corrected
> here rather than reconciled silently.

The ML-DSA analogue is F204-11 / F204-15, where `generateKeyPairFromSeed` (`keys.ts:60`) is
kept out of `index.ts`'s export block and the package declares a single `"."` export. The
same pattern would apply to `slh_keygen_internal` and `slh_sign_internal`.

### 3.7 F205-11, F205-12 — RBG failure indication

The `⊥`-on-RBG-failure pattern appears at two points, verified in the PDF:

- **Algorithm 21** (`slh_keygen`), steps 4–6 — a single guard covering all three values:
  `if SK.seed = NULL or SK.prf = NULL or PK.seed = NULL`.
- **Algorithms 22 and 23** (`slh_sign`, `hash_slh_sign`), steps 5–7 — on `addrnd`, with the
  marginal note "skip lines 4 through 7 for the deterministic variant".

⚠️ **Checked against the ML-KEM work, as instructed: it does not transfer.** The
`RbgFailureError` type lives in `packages/core/src/vendor/ml-kem/ml-kem.ts` and the
`RBG_FAILURE` mapping is in `encapsulateTo` (`algorithms.ts`). Both reach the ML-KEM path
only. `FIPS-204-MATRIX.md` §3.3 already records the probe showing ML-DSA keygen and signing
leak a raw upstream `Error` instead. SLH-DSA, being unimplemented, has no path at all — so
the answer here is "not applicable", not "covered".

Note the step numbers differ slightly from the work order, which cited "Algorithm 22/23 steps
4-7". Line 4 is the sampling itself (`addrnd ← 𝔹ⁿ`); the NULL guard is lines 5–7. Recorded
as 5–7 in the row.

### 3.8 F205-13, F205-14 — Context string

The 255-byte cap matches FIPS 204 (F204-16), but **FIPS 205 splits it into two rows with
different prescribed responses**, and that asymmetry is the reason both are registered:

- **Algorithms 22 and 23** (signing): `return ⊥` — "an error indication".
- **Algorithms 24 and 25** (verification): `return false` — a boolean, not an error.

FIPS 204's Algorithm 2 states only the signing side; its verification algorithms do not carry
an equivalent explicit context guard. A later phase must not collapse F205-13 and F205-14
into a single row by analogy with F204-16.

On the work order's question of whether `sign.ts` handles this for SLH-DSA: **it is not
wired up.** `sign.ts` is ML-DSA-only — `sign` takes `SecretKey<'ml-dsa-65'>` and `verify`
takes `PublicKey<'ml-dsa-65'>`. The existing `MAX_CONTEXT_LENGTH = 255` at `sign.ts:6` cites
FIPS 204 §5.2 and governs the ML-DSA path alone.

### 3.9 F205-15 … F205-19 — Pure vs. pre-hash (HashSLH-DSA)

**Verified before writing these rows, as the same discipline required for HashML-DSA in
`FIPS-204-MATRIX.md` §3.9.**

- The provider implements pre-hash: `slh-dsa.d.ts:96` declares
  `prehash: (hash: TArg<CHash>) => TRet<Signer>`, and every one of the 12 exported parameter
  sets carries it ("Also exposes `.prehash(...)`" in each JSDoc block).
- The SDK references neither the pure nor the pre-hash SLH-DSA surface. There is no import of
  `@noble/post-quantum/slh-dsa.js` anywhere in `packages/core/src` or `packages/cli/src`.

So unlike ML-DSA — where the pure variant is exposed and only HashML-DSA is not — **neither
SLH-DSA variant is reachable**, and these rows are not applicable for the broader reason
given in §1.3.

F205-16 rests on an undefined `must` and would, if ever activated, be unsatisfiable by this
library alone: FIPS 140 validation is a property of a module, not of a package.

### 3.10 F205-20 — Hedged vs. deterministic signing

Same shape as ML-DSA's §3.4 split, with a different mechanism: FIPS 205 Algorithm 19 line 2
substitutes `opt_rand ← PK.seed` for the deterministic variant, rather than zeroing a random
value as ML-DSA does.

What the provider **is**, recorded without evaluation: `slh-dsa.js:385-388` maps
`extraEntropy === false` to `random = copyBytes(pkSeed)` — precisely the standard's
substitution — and `extraEntropy === undefined` to `randomBytes(N)`, the hedged default.

`FIPS-204-MATRIX.md` §3.7 settled the equivalent ML-DSA question by finding that
`toNobleOptions` (`sign.ts:14-25`) constructs a fresh options object and discards
`extraEntropy`, making the deterministic variant unreachable. **That finding is about
`sign.ts`'s ML-DSA path and says nothing about a future SLH-DSA path**, which would need its
own analysis.

### 3.11 F205-21 — Parameter sets

FIPS 205 Table 2 defines 12 parameter sets: SHA2 and SHAKE, at 128/192/256, in `s` (small
signature) and `f` (fast) variants.

| Parameter set family | 𝑛   | Category | pk bytes | sig bytes |
| -------------------- | --- | -------- | -------- | --------- |
| SHA2/SHAKE-128s      | 16  | 1        | 32       | 7 856     |
| SHA2/SHAKE-128f      | 16  | 1        | 32       | 17 088    |
| SHA2/SHAKE-192s      | 24  | 3        | 48       | 16 224    |
| SHA2/SHAKE-192f      | 24  | 3        | 48       | 35 664    |
| SHA2/SHAKE-256s      | 32  | 5        | 64       | 29 792    |
| SHA2/SHAKE-256f      | 32  | 5        | 64       | 49 856    |

**Provider vs. SDK exposure — no parity, and the gap is total:**

|                       | Exported by `@noble/post-quantum@0.7.1`                   | Registered in the SDK |
| --------------------- | --------------------------------------------------------- | --------------------- |
| SHAKE family (6 sets) | `slh_dsa_shake_{128,192,256}{s,f}` — `slh-dsa.js:622-652` | **none**              |
| SHA2 family (6 sets)  | `slh_dsa_sha2_{128,192,256}{s,f}` — `slh-dsa.js:784-814`  | **none**              |

The provider covers Table 2 **exactly** — 12 of 12, with no extras and no omissions.
The SDK registers **0 of 12**.

Two structural blockers a later phase will hit, both already recorded for ML-DSA in
`FIPS-204-MATRIX.md` §3.1 and unchanged since:

- `types.ts:10` declares `SignatureAlgorithm = 'ml-dsa-65'`, a closed single-member union.
- `algorithms.ts:45` types `SignerSpec.signer` as `typeof ml_dsa65` — a **concrete** type,
  not a structural interface. ML-KEM has `NobleKem` for this purpose; the signature side has
  no equivalent. Registering any second signer — ML-DSA-44, ML-DSA-87 or any SLH-DSA set —
  requires that refactor first.

The signature sizes are also an integration consideration rather than a conformance one, and
are noted so a later phase costs them deliberately: at 7 856–49 856 bytes, SLH-DSA signatures
are 2× to 15× the 3 309-byte ML-DSA-65 signature.

---

## 4. Summary

Registry pass — **no conformity determinations were made**.

| Status         | Count  | Req IDs           |
| -------------- | ------ | ----------------- |
| NOT APPLICABLE | 21     | F205-01 … F205-21 |
| **Total**      | **21** |                   |

Every row is `NOT APPLICABLE` for one reason: **SLH-DSA is not implemented by this SDK**
(§1.3). This is an applicability finding verified against the code, not a conformity
judgement, and it is uniform across the table rather than row-specific.

### 4.1 What this document does not say

- It does not claim FIPS 205 conformance, in whole or in part. There is nothing to conform.
- It does not claim any requirement is breached.
- It makes no claim about the provider's SLH-DSA implementation. `slh-dsa.js` was inspected
  only for its **export surface** and for the two facts recorded in §3.9 and §3.10. Its
  arithmetic, zeroization and RBG behaviour are unexamined.
- It makes no claim of FIPS validation. Nothing in this repository has been submitted to, or
  evaluated under, the NIST CMVP or CAVP.
- It records no ACVP evidence: the repository carries no SLH-DSA vectors.

### 4.2 Entry conditions for an implementation phase

1. Refactor `SignerSpec.signer` from `typeof ml_dsa65` to a structural interface before
   registering any SLH-DSA parameter set (§3.11).
2. Decide which of the 12 sets to expose. Availability in the provider is not conformance;
   each set needs its own pass over this matrix.
3. Read `slh-dsa.js` before assigning any status — especially F205-06 (§3.4) and F205-03
   (§3.2). Neither the ML-KEM nor the ML-DSA finding transfers.
4. Treat F205-13 and F205-14 as separate rows: signing returns `⊥`, verification returns
   `false` (§3.8).
5. Do not assume the `RBG_FAILURE` work covers SLH-DSA keygen or signing (§3.7).
6. Carry the §1.3 boundary into every conclusion: SLH-DSA would be **Provider-scope**, since
   `ml-dsa.js` and `slh-dsa.js` are not vendored as `ml-kem.ts` is.

### 4.3 Change log

| Date       | Change                                                                                                                                                                                               |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-09-08 | Registry pass (Phase 1). 21 rows registered from FIPS 205; all NOT APPLICABLE, SLH-DSA being unimplemented. Provider exports all 12 Table 2 parameter sets; the SDK registers none. No code changed. |
