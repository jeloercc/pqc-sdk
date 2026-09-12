# @pqc-sdk/core

## 0.9.1

### Patch Changes

- c582138: Added a "FIPS 203/204/205 conformance self-assessment" section to README.md, linking the three clause-by-clause matrices under `docs/compliance/` (FIPS-203, FIPS-204, FIPS-205), summarizing the six findings closed by code changes (F203-11, F203-18, F203-19, F204-08, F204-10, F204-13), and stating plainly what is not claimed: this is self-assessment rather than CMVP validation, most `INDETERMINATE` rows depend on the host platform's RBG, and SLH-DSA remains deliberately unimplemented.

  Docs only — no code, no published package output changed.

- b3359ba: Published the FIPS 203/204/205 compliance matrices on the docs site under `/compliance/`, synced from `docs/compliance/*-MATRIX.md` by the same mechanism `scripts/sync.mjs` already uses for the Compatibility page, plus a hand-written index page and nav/sidebar entries.

  Docs site only — no code, no published package output changed.

## 0.9.0

### Minor Changes

- f8b4a23: Expose ML-DSA-44 and ML-DSA-87, closing the last PARTIALLY CONFORMING row in FIPS-204-MATRIX.md

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

- f8b4a23: `verify` now returns `false` for a wrong-length ML-DSA public key instead of throwing

  FIPS 204 §3.6.2 makes the manner of the response part of the requirement: "If an
  implementation of ML-DSA can accept inputs for σ or pk of any other length, it **shall
  return false** whenever the lengths of either of these inputs differ from their lengths
  specified in this standard."

  The signature half already behaved this way — a wrong-length σ verifies to `false`. The
  public-key half did not: `requireKey` threw `PqcError('INVALID_KEY')`, and it ran before
  the try block in `verify`, so the rejection never reached the catch that would have
  normalised it to `false`.

  **Observable behaviour change.** Code that currently relies on the throw will break:

  ```ts
  // Before: rejected with PqcError('INVALID_KEY')
  // Now:    resolves to false
  await pqc.verify(message, signature, { algorithm: 'ml-dsa-65', use: 'public', bytes });
  ```

  Any `try`/`catch` around `pqc.verify` that treated `INVALID_KEY` as "the caller supplied a
  mis-sized verification key" no longer fires for that case. A caller that already treated a
  `false` result as "do not trust this signature" needs no change — the outcome is the same
  answer delivered through the return value instead of an exception, and the behaviour was
  fail-closed before and remains so.

  **The change is scoped to `verify` only.** `requireKey` is unmodified, and every other
  operation keeps the SDK-wide convention of throwing `INVALID_KEY` for a malformed key:
  `encrypt`, `decrypt`, `sign`, `encryptStream`, `decryptStream` and the Web Stream variants
  are untouched. A bad key there is an operator error with no meaningful "no" to return;
  `verify` is the one operation whose contract is a boolean, and the one the standard names.

  The carve-out covers **length only**. `verify` still throws for every other malformed-key
  condition — `WRONG_ALGORITHM` for a non-ML-DSA key, `WRONG_KEY_USE` for a secret key passed
  as public, `UNSUPPORTED_ALGORITHM` for an unknown algorithm — and still throws
  `INVALID_CONTEXT` for a context string over 255 bytes.

  Two regression tests were added to `sign.test.ts`: one covering five wrong public-key
  lengths (0, 1951, 1953, and the 1312/2592 lengths that are _valid_ for ML-DSA-44 and
  ML-DSA-87), mirroring the coverage that already existed for signature length; and one
  pinning that the carve-out did not widen, so a future change relaxing `requireKey` globally
  fails immediately.

  No key, signature or envelope format changed. See `docs/compliance/FIPS-204-MATRIX.md`
  §3.4 for the evidence and the row this closes (F204-08).

- f8b4a23: Vendor the ML-DSA primitive and close two FIPS 204 findings

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

- f8b4a23: Vendor the ML-KEM primitive and close two FIPS 203 findings

  The ML-KEM surface of `@noble/post-quantum@0.7.1` (`ml-kem.ts`, `_crystals.ts`,
  `utils.ts`) is now vendored into `packages/core/src/vendor/ml-kem/` under its MIT
  license, and `ml-kem-768` resolves to that copy. X-Wing, ML-DSA and SLH-DSA continue to
  resolve against the npm package unchanged.

  This was necessary because the published `dist` imports `@noble/post-quantum` as an
  external runtime import: consumers execute their own registry-resolved copy, so no patch
  or override in this repository could ever have reached them. Two corrections now ship:

  - **F203-19** — `Compress_d` used IEEE-754 floating-point division (`Q / 2` is 1664.5),
    which FIPS 203 §3.3 and §4.2.1 prohibit outright. It is now BigInt integer arithmetic.
    Output is unchanged: verified bit-exact across all 36,619 `(i, d)` pairs of the
    complete domain, against both the previous implementation and the §4.2.1 definition
    evaluated in exact rationals.
  - **F203-11** — a platform RBG failure during encapsulation was reported as
    `INVALID_KEY`, telling callers the recipient's key was malformed when it was not.
    FIPS 203 Algorithm 20 steps 2-4 define it as a separate condition, and it now surfaces
    as the new `RBG_FAILURE` error code.
  - **F203-18** — decapsulation selected the shared secret with a ternary on the secret
    implicit-reject flag, and used a second ternary to decide which candidate to zeroize.
    FIPS 203 §6.3 requires that flag to be destroyed before the algorithm terminates.
    Selection is now byte-wise mask arithmetic into a fresh buffer and both candidates are
    destroyed unconditionally, at both `decapsulate` call sites. Output is unchanged on
    both branches: the ACVP vectors still pass, and the reject path still returns exactly
    `J(z ‖ c)`. This removes the branch from the source, not from the machine —
    JavaScript provides no verifiable constant-time guarantee, and that limitation is
    documented rather than claimed closed.

  No ciphertext, key or envelope format changed, so no golden vectors were regenerated and
  no migration is needed. The 31 ACVP known-answer vectors pass unchanged against the
  vendored path.

  **New error code:** `RBG_FAILURE` is added to `PqcErrorCode`. Code that exhaustively
  switches on that union will need a new branch. Code that previously matched
  `INVALID_KEY` to detect entropy failures — behaviour that was never correct — will no
  longer match.

  `@noble/curves` and `@noble/hashes` become direct runtime dependencies of
  `@pqc-sdk/core` (both pinned to 2.4.0, the versions `@noble/post-quantum@0.7.1` itself
  depends on). They were already installed transitively; the vendored code imports them
  directly, so declaring them is correctness, not a new install.

  `SECURITY.md` gains a "Randomness source" section documenting which randomness API each
  supported runtime resolves to, and stating explicitly that SP 800-90A/B/C validation of
  that generator is the deployer's responsibility, not this SDK's (FIPS 203 §3.3).

  See `docs/compliance/FIPS-203-MATRIX.md` §3.4, §3.8 and §3.9 for the evidence, and
  `packages/core/src/vendor/ml-kem/NOTICE.md` for provenance and the re-vendoring
  procedure.

- f8b4a23: Repoint X-Wing's embedded ML-KEM-768 at the vendored, FIPS-corrected primitive

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

### Patch Changes

- cefdd68: `encrypt` and `encryptStream` now fail with `PqcError('INVALID_KEY')` when a
  KEM public key is the right length but not a valid encapsulation key, instead
  of letting a raw `@noble` error escape.

  This is reachable with an X-Wing public key whose `pk_X` half is a small-order
  X25519 point (`0`, `1`, either order-8 point, or `p-1`): `@noble/curves`
  throws because those drive the shared secret to all-zero. The behaviour was
  already fail-closed — nothing was decryptable and no plaintext leaked — but
  the error crossed the API boundary unmapped, contrary to the documented
  contract that failures surface as a `PqcError`. `decrypt` already mapped the
  equivalent decapsulation case.

  Also adds a public-key mutation matrix (`key-mutations.test.ts`), covering the
  `pk_M` and `pk_X` regions of X-Wing keys, ML-KEM-768 encapsulation keys, and
  degenerate `ct_X` on decapsulation — regions no suite previously tampered.

- f8b4a23: Record SLH-DSA (FIPS 205) as a deliberate scope decision, not an oversight

  Documentation only — no API or behavior change. `README.md` and `SECURITY.md` gain a
  short section stating that SLH-DSA is not implemented by choice: its signatures run
  7,856–49,856 bytes (FIPS 205 Table 2, SLH-DSA-128s through 256f) versus 3,309 bytes for
  ML-DSA-65; SPHINCS+'s hash-based construction costs tens of thousands of hash-function
  invocations per signing/verification operation with no native acceleration available in
  pure JS; and SLH-DSA's target use cases — firmware signing, long-lived roots of trust,
  hedging against a lattice cryptanalytic break — aren't this SDK's request/response and
  file-level target. ML-DSA-65 is recorded as the recommended signature algorithm, and a
  consumer with a genuine SLH-DSA requirement is pointed toward a CMVP-validated module
  rather than a self-assessed JS library.

  `docs/compliance/FIPS-205-MATRIX.md` §1.3 records the same reasoning with a date
  (2026-09-09) and explicit reopening conditions (§4.2, unchanged). All 21 rows stay
  `NOT APPLICABLE` — what changes is that the reason is now a recorded decision rather than
  a bare "not implemented," and the existing registry (all 12 Table 2 parameter sets mapped
  against every applicable FIPS 205 requirement) is what makes that decision credible rather
  than arbitrary.

## 0.8.4

[This release was published to npm on 2026-09-04 (tags `@pqc-sdk/core@0.8.4` /
`@pqc-sdk/cli@0.8.4`, commit `0aa0e69`), but its version commit was lost when
`main` was force-pushed on 2026-09-06. Entries below are restored verbatim
from the tagged commit.]

### Patch Changes

- b2d0498: `encrypt` and `encryptStream` now fail with `PqcError('INVALID_KEY')` when a
  KEM public key is the right length but not a valid encapsulation key, instead
  of letting a raw `@noble` error escape.

  This is reachable with an X-Wing public key whose `pk_X` half is a small-order
  X25519 point (`0`, `1`, either order-8 point, or `p-1`): `@noble/curves`
  throws because those drive the shared secret to all-zero. The behaviour was
  already fail-closed — nothing was decryptable and no plaintext leaked — but
  the error crossed the API boundary unmapped, contrary to the documented
  contract that failures surface as a `PqcError`. `decrypt` already mapped the
  equivalent decapsulation case.

  Also adds a public-key mutation matrix (`key-mutations.test.ts`), covering the
  `pk_M` and `pk_X` regions of X-Wing keys, ML-KEM-768 encapsulation keys, and
  degenerate `ct_X` on decapsulation — regions no suite previously tampered.

## 0.8.3

### Patch Changes

- eb02367: Bump the pinned `@noble/post-quantum` from 0.6.1 to 0.7.1.

  0.6.1 is outside upstream's support window (their `SECURITY.md` supports
  `>=0.7.1`), so it no longer receives security fixes. 0.7.1 adds input
  validation, broader zeroization of internal buffers, and detaches
  caller-owned buffers on the hybrid key paths.

  No output or format change. 0.7.0 removed the legacy `XWing` alias, so the
  `x-wing` spec entry now imports `ml_kem768_x25519` — the same construction
  under its current name. The X-Wing combiner and seed expansion are
  byte-identical, and the ML-KEM `BaseCaseMultiply` change is an equivalent
  reduction ordering, not a corrected result. Verified by the NIST ACVP
  vectors, the X-Wing draft-10 Appendix C vectors, and the golden vectors,
  which decrypt pre-existing 0.6.1-era ciphertexts unchanged.

## 0.8.2

### Patch Changes

- ce038b6: Fixes a documentation defect that mattered: the hybrid-encryption and streaming guides still described `ml-kem-768` as the algorithm `pqc.keys.generate()` returns, contradicting the README and, in the hybrid guide, contradicting itself two sections later. X-Wing has been the default since 0.8.0. In a cryptography library a stale default in the docs is a real hazard — a reader following the guide would believe they had a pure-PQ key where the SDK produced a hybrid one, or the reverse. Every statement of the default now agrees, and the algorithm-comparison table was rebuilt with X-Wing first (its rows had been left in the old column order) plus a FIPS-scope row.

  Makes existing streaming guarantees discoverable without reading source. The streaming guide gains a section on how each chunk is bound to its position and to the stream: the 11-byte big-endian chunk counter and final-chunk flag forming the nonce, the header bound as AAD on every chunk, fresh KEM encapsulation per stream, and the rule that a stream may only end after a chunk that authenticated as final. It also documents that the mutation matrix tests all of this adversarially against both KEMs, enumerating what it covers.

  Adds a visible security-status note to the README: no independent third-party audit, no constant-time guarantees, no memory zeroization, linking `SECURITY.md` for the full threat model.

  Reframes the "PQC in 30 minutes" claim to be about the API surface specifically, and says plainly that key management, format versioning, rotation and interoperability are the hard parts of a real migration and remain the adopter's problem.

## 0.8.1

### Patch Changes

- a318274: Accuracy pass over the project's public claims, plus better placement for the evidence behind them.

  **Corrected overclaims.** `Bun` and `Browsers` were marked ✅ in the core README's compatibility table with no roundtrip ever executed on either — the same class of inaccuracy as audit finding M2. Both are now ⏳ with the reason stated. The Cloudflare Workers bundle figure said 78 KiB / 20 KiB gzip, measured in July before X-Wing and streaming landed; re-measured with `wrangler deploy --dry-run` it is 161 KiB / 43 KiB gzip, and the docs now say so, note what changed, and tell size-sensitive readers to measure rather than quote. The React Native row now states that streaming needs a `Symbol.asyncIterator` alias and that the Web Streams adapters do not work on Hermes. The npm package descriptions omitted X-Wing, which has been the default KEM since 0.8.0.

  **Evidence moved up front.** The README's "How this is verified" section now precedes the quickstart and opens with the strongest signals: NIST ACVP vectors running in CI, five runtimes validated by actual execution (including a physical Android device), parser fuzzing, property tests, golden wire-format vectors and the streaming mutation matrix.

  **Process stated plainly.** `CONTRIBUTING.md` gains a "Development process" section: development is AI-assisted, every commit carries a `Co-Authored-By` trailer, and the working agreements are checked in rather than hidden. It links `.claude/rules/crypto-review.md` as the standing discipline and is explicit that none of it substitutes for an independent third-party audit, which this project has not had.

  No code or behaviour changes.

## 0.8.0

### Minor Changes

- 0242754: **BREAKING: `pqc.keys.generate()` with no arguments now returns an X-Wing hybrid pair (X25519 + ML-KEM-768), not pure ML-KEM-768.** The TypeScript overload changed from `Promise<KeyPair<'ml-kem-768'>>` to `Promise<KeyPair<'x-wing'>>`. **JavaScript consumers get no compile-time signal at all** — code calling `generate()` silently starts producing X-Wing keys, with different key sizes and a `pqcenc.v2` envelope. Anyone persisting keys from `generate()` must now decide deliberately. To keep the previous behaviour: `pqc.keys.generate({ algorithm: 'ml-kem-768' })`. Read [docs/MIGRATION-0.8.md](https://github.com/jeloercc/pqc-sdk/blob/main/docs/MIGRATION-0.8.md) before upgrading.

  The CLI moves with it: `pqc keygen` with no `--algorithm` and `pqc init` development keys are now `x-wing`, so default key files are named `x-wing.public.pqc` / `x-wing.secret.pqc` rather than `ml-kem-768.*`. An SDK defaulting to hybrid while the CLI defaulted to pure would be worse than either consistent posture.

  Why: a hybrid KEM survives the failure of either half, and ML-KEM-768 is young enough that a cryptanalytic result would leave a pure-PQ ciphertext with nothing to fall back on. This is the current consensus for new protocols — TLS 1.3's `X25519MLKEM768`, Signal's PQXDH, Apple's PQ3, and BSI and ANSSI recommendations. The flip was previously announced for v1.0; at 0.x the break is cheap and expected, and shipping the weaker default for longer was the worse trade.

  **Pure ML-KEM-768 remains a first-class choice, not a legacy mode**, and is the right call in two cases: FIPS certification scope (X-Wing is a CFRG draft, not covered by FIPS 203, so a compliance regime requiring a certified KEM needs the pure one), and size or speed (32 bytes less per envelope; keygen 0.65 ms vs 1.56 ms, encrypt 1 KiB 0.80 ms vs 3.31 ms, decrypt 1 KiB 1.04 ms vs 3.38 ms on this repo's CI runner).

  No serialized layout changed. `pqcenc.v1` and `pqcenc.v2` have coexisted since 0.5.0, `decrypt` dispatches on the version byte, and the golden vectors are untouched — every artifact produced by 0.7.x stays valid and decryptable. Mixed fleets: a peer on ≤0.4.x cannot read a `pqcenc.v2` envelope, so upgrade readers before writers, or pin writers to `ml-kem-768` until you can.

### Patch Changes

- fab1693: `pqc audit` now states its limits wherever it speaks. The help text, the runtime banner, and both READMEs describe it as a heuristic, non-exhaustive regex scan — a starting point for a migration review, not a substitute for one. A clean run says so explicitly ("not a clean bill of health: it means the patterns above did not match, not that none exists") rather than leaving "No pre-quantum crypto detected" to be read as a guarantee, and findings are framed as candidates to confirm rather than a finished migration list. The scan itself is unchanged; only its framing is.

  Documentation: a new **How this is verified** section in the root README maps each layer the SDK actually owns — envelope format, key serialization, nonce derivation, fail-closed parsing — to the suite that covers it, linking the NIST ACVP vectors, golden serialization vectors, parser fuzzing, `fast-check` property tests, the streaming mutation matrix, the format spec, the audit and security reviews, and the runtime compatibility record. It also states plainly that those reviews are internal and AI-assisted rather than an independent third-party audit, and surfaces the absence of memory zeroization from `SECURITY.md` into the README where adopters will actually see it.

## 0.7.1

### Patch Changes

- a337529: Documentation only: `docs/compatibility.md` now records the React Native rows as ✅ for the async-iterable core path, validated on a physical Android device via Expo Go (SDK 54) with genuine native entropy from `react-native-get-random-values`. ML-KEM-768, X-Wing, ML-DSA-65, streaming roundtrips for both KEMs, and the streaming tamper case (rejected with `PqcError` `DECRYPTION_FAILED`) all pass on device, with per-step timings recorded. The Hermes standalone engine rows are closed in the same pass for X-Wing and streaming.

  The Web Streams adapters (`encryptWebStream`/`decryptWebStream`) stay ❌ on React Native — Hermes provides no `TransformStream`/`ReadableStream` and RN does not polyfill them. That is a permanent platform fact rather than a pending item, and the doc names the async-iterable core as the supported path on that runtime.

  No code change: no published API, envelope layout or behaviour is affected.

## 0.6.0

### Minor Changes

- 944a70c: Streaming encryption (`docs/proposals/streaming-encryption.md`) is now public: `pqc.encryptStream`/`pqc.decryptStream` for arbitrarily large payloads without holding them fully in memory, plus `pqc.encryptWebStream`/`pqc.decryptWebStream` (thin `TransformStream` adapters for `pipeThrough`/`pipeTo` pipelines) — both ML-KEM-768 and X-Wing supported from day one. New `pqcenc` envelope version bytes `0x03` (ml-kem-768 streaming) and `0x04` (x-wing streaming), additive alongside the existing v1/v2 one-shot envelopes, which are byte-for-byte unchanged.

  `pqc.decryptStream` has an incremental-release property one-shot `pqc.decrypt` does not: it yields each plaintext chunk as soon as that chunk authenticates, so a truncated or tampered stream can yield genuine prefix chunks before throwing. Only the async iterable completing without throwing means the full plaintext is authentic and complete — see the JSDoc on `decryptStream` for the full explanation and a worked example of handling this correctly.

  Verified end-to-end with real large-file roundtrips on Node (`fs` streams via `Readable.toWeb`/`Writable.toWeb`), Deno (native `Deno.FsFile` streams), and Cloudflare Workers (in-memory, workerd's `TransformStream`) — see `docs/compatibility.md`. Hermes and React Native stay ⏳, tracked by issue #45.

## 0.5.0

### Minor Changes

- ce2fa4c: X-Wing is now a fully supported algorithm across the public API and CLI: `SUPPORTED_ALGORITHMS` includes `'x-wing'`, and `KEM_NAMES` is exported for introspection. `pqc keygen --algorithm x-wing` generates a hybrid key pair, and `pqc encrypt`/`pqc decrypt` accept either KEM key (`ml-kem-768` or `x-wing`) and write/read the matching envelope version automatically — `readKeyFile`'s expectation loosened from "exactly ml-kem-768" to "any KEM key," reporting the algorithm actually found on a mismatch. `pqc audit` migration hints now mention x-wing for long-term data. `pqc.keys.generate()` with no arguments is unchanged (`ml-kem-768`); the default flips to `x-wing` at v1.0 as previously announced.
- 7340a0d: New `x-wing` KEM algorithm (X25519 + ML-KEM-768 hybrid per draft-connolly-cfrg-xwing-kem-10): `pqc.keys.generate({ algorithm: 'x-wing' })` generates a pair (1216-byte public key, 32-byte seed secret key) that serializes with the existing `pqcv1` token format, validated against the draft's Appendix C test vectors. The hybrid envelope format (`pqcenc.v2`) is not implemented yet — `encrypt`/`decrypt` fail closed with `UNSUPPORTED_ALGORITHM` on x-wing keys until it lands. The no-argument `keys.generate()` default is unchanged (`ml-kem-768`).
- 79d4565: Hybrid envelope v2 (`pqcenc.v2`): `pqc.encrypt` with an `x-wing` public key now produces a v2 envelope (version byte `0x02`, X-Wing ciphertext `ct_M ‖ ct_X`, AES-256-GCM keyed by the draft's SHA3-256 combiner output used verbatim — see `docs/serialization-format.md` §2.2), and `pqc.decrypt` dispatches on the version byte, accepting both v1 and v2. The Day-1 `UNSUPPORTED_ALGORITHM` guard on x-wing keys is removed; `encrypt`/`decrypt` signatures widen to any KEM key. This is the additive layout change acknowledged in `docs/proposals/hybrid-envelope.md` §3: every v1 artifact remains valid and byte-identical (v1 golden vectors untouched), so no major bump. Caveat for mixed-version fleets: peers on ≤0.4.x cannot decrypt v2 envelopes — upgrade readers before writers.

## 0.4.1

### Patch Changes

- 4198e0b: Error messages that echo a segment of an untrusted serialized key (unknown algorithm or key-use in `pqc.keys.deserialize`) now truncate the echoed value to 32 characters, so a malformed input can never inject unbounded content into errors that end up in logs.

## 0.3.9

### Patch Changes

- 459b64f: Lock the serialization formats across versions: normative spec in `docs/serialization-format.md` (key token layout, hybrid ciphertext byte layout, signature encoding, CLI key files, error contract, forward-compatibility rules) plus golden-vector tests generated with the published 0.3.8 — serialized keys for both algorithms and uses, a complete ciphertext, and a signature that every future version must keep deserializing and using correctly. Unknown version markers (`pqcv2` tokens, unknown ciphertext version byte) are pinned to fail closed with clear `PqcError` codes.

## 0.3.8

### Patch Changes

- 184516d: Add performance benchmarks for the five core operations (ML-KEM-768 keygen/encrypt/decrypt, ML-DSA-65 keygen/sign/verify) with automatic regression detection in CI: every PR reports the measured numbers and fails when any operation exceeds 2.5x the committed baseline. `generateKeyPairFromSeed` now returns the narrow `KeyPair<A>` type inferred from its algorithm argument (type-level only, no runtime change).

## 0.3.7

### Patch Changes

- b429873: Docs only: mark React Native as validated in the compatibility matrix. The full ML-KEM-768 encrypt/decrypt and ML-DSA-65 sign/verify roundtrip ran on a physical Android device via Expo Go (SDK 54) with genuine native entropy from `react-native-get-random-values`.

## 0.3.6

### Patch Changes

- bd18bea: Roll `examples/react-native-expo` back to Expo SDK 54 (from SDK 56). The Expo
  Go client actually installed on the test device is v54.0.8, which only
  supports SDK 54 — Play Store rollout of newer Expo Go builds lags per-device,
  so the example tracks what is installable on the test hardware, not the
  latest SDK. `expo install expo@^54.0.0 --fix` realigned `react-native`
  (0.85.3 → 0.81.5), `expo-status-bar`, `react`, and `typescript`; the
  `expo-status-bar` config-plugin entry was removed from `app.json` because the
  package does not ship a config plugin on SDK 54. `expo-doctor` reports 18/18
  checks passing and `npx expo export --platform android` bundles cleanly (588
  modules) with `react-native-get-random-values` imported before
  `@pqc-sdk/core`. `docs/compatibility.md` is updated to reflect the SDK 54
  target. No runtime or public API change.

## 0.3.5

### Patch Changes

- 273cefe: Fold `prettier --check .` into the `lint` turbo task (as a `//#format:check`
  root task dependency), so a single `pnpm lint` — locally and in CI — surfaces
  formatting issues alongside eslint/tsc, instead of relying on a separate
  `format:check` step that's easy to skip when running the gate by hand. Removes
  the now-redundant standalone "Format check" step from `.github/workflows/ci.yml`.
  No runtime or public API change.
- 273cefe: Pin `examples/react-native-expo` back to Expo SDK 56 (from SDK 57). Expo Go's
  Play Store release does not support SDK 57 yet — its build is still in app
  store review — so the example targets the SDK that Expo Go can actually run
  today. `expo install expo@^56.0.0 --fix` realigned `react-native` (0.86.0 →
  0.85.3), `expo-status-bar`, and `typescript`; `expo-doctor` reports 21/21
  checks passing and `npx expo export --platform ios` still bundles cleanly
  with `react-native-get-random-values` imported before `@pqc-sdk/core`.
  `docs/compatibility.md` is updated to reflect the SDK 56 target and note that
  SDK 57 support is pending Expo Go's own store approval, not a PQC SDK
  limitation. No runtime or public API change.

## 0.3.4

### Patch Changes

- 914b654: Fold `prettier --check .` into the `lint` turbo task (as a `//#format:check`
  root task dependency), so a single `pnpm lint` — locally and in CI — surfaces
  formatting issues alongside eslint/tsc, instead of relying on a separate
  `format:check` step that's easy to skip when running the gate by hand. Removes
  the now-redundant standalone "Format check" step from `.github/workflows/ci.yml`.
  No runtime or public API change.

## 0.3.3

### Patch Changes

- 744d59e: Add `examples/react-native-expo`, a real Expo (TypeScript) app that validates
  `@pqc-sdk/core` with the genuine `react-native-get-random-values` entropy
  polyfill (native OS randomness), not the `Math.random` shim used for the
  Day-0 standalone Hermes engine test. The app type-checks and bundles cleanly
  through Metro (595 modules, Hermes bytecode output) with no simulator/emulator
  available in this environment to run it on-device; `docs/compatibility.md` is
  updated to "harness ready, on-device run pending" rather than a false ✅, with
  the concrete findings (Metro bundle succeeds; standalone Hermes execution of
  the real RN bundle fails on bytecode-version mismatch and on private
  class-field syntax in the `react-native` package itself).

  Also pins `typescript` as an explicit devDependency in `@pqc-sdk/core` and
  `@pqc-sdk/cli` (previously relied on hoisting from the workspace root).
  Adding the Expo example introduced a second `typescript` version into the
  workspace, which made `tsup`'s peer resolution for its DTS build
  nondeterministic and broke `@pqc-sdk/core`'s build; pinning the version
  locally removes the ambiguity regardless of what other workspace packages
  require. No runtime or public API change.

## 0.3.2

### Patch Changes

- 04bc7b4: Add fast-check fuzzing for the `deserialize` parser, the SDK's primary attack
  surface for untrusted input. The suite asserts a single fail-closed invariant
  over thousands of hostile tokens — arbitrary/unicode/control-char strings,
  wrong segment counts, unknown algorithms and uses, valid base64url of the wrong
  length, off-by-one lengths, invalid and non-canonical base64url, the impossible
  `% 4 === 1` length, truncated prefixes, and injected dots — across both the
  untyped and typed (`{ algorithm, use }`) overloads: `deserialize` either returns
  a structurally consistent key or throws a `PqcError`, never anything else.
  Hand-picked regressions name the nastiest cases, and the truncation case covers
  every prefix slice of a valid token. Test-only; no API or runtime change.

## 0.3.1

### Patch Changes

- 6fcd7a4: Stabilize the multi-megabyte encrypt/decrypt round-trip test against CI flakes.
  It ran on the default 5s timeout, which is too tight when `turbo run test`
  executes the core and CLI suites concurrently and v8 coverage instrumentation
  slows the 3 MB operation under CPU contention. Give it a generous explicit
  timeout so it cannot flake. Test-only; no API or runtime change.
- 6fcd7a4: Add property-based tests (fast-check) that assert the core crypto invariants
  over many generated inputs, complementing the example-based suite:
  `decrypt(encrypt(x))` round-trips for any payload; any single-byte tamper of a
  ciphertext fails closed with a `PqcError` and never returns plaintext;
  `deserialize(serialize(k))` preserves any key; a genuine signature verifies and
  any single-byte tamper of the signature or message is rejected; and base64url
  round-trips for any byte array. Runs are seeded for deterministic CI and bounded
  so test time stays modest. Dev-dependency and tests only; no API or runtime
  change.
- 6fcd7a4: Close the last open edge-case coverage gap from the June 2026 audit (finding
  I1): the `verify` defense-in-depth catch path is now exercised by a focused
  regression test. It proves `verify` fails closed to `false` if the underlying
  signer ever throws — no signature byte-pattern makes `@noble`'s verify throw in
  practice (it returns `false` for every malformed signature), so the signer is
  stubbed to throw to genuinely cover the branch. Test-only; no API or runtime
  behavior change.

## 0.3.0

### Minor Changes

- 499b31f: Harden the core API and crypto surface:

  - `deserialize(token, { algorithm, use })` is a new typed overload that returns a
    narrow key type (e.g. `PublicKey<'ml-kem-768'>`), so deserialized keys drop
    straight into `encrypt`/`sign` without an `as never` cast. A mismatch throws
    `WRONG_ALGORITHM` or `WRONG_KEY_USE`. The `ExpectedKey` type is now exported.
  - Signature `context` longer than the FIPS 204 limit of 255 bytes now throws a
    `PqcError('INVALID_CONTEXT')` consistently from both `sign` and `verify`
    (previously `sign` leaked a raw error and `verify` silently returned `false`).
  - `decapsulate` now runs inside `decrypt`'s try/catch, so any unexpected throw is
    normalized to the documented `DECRYPTION_FAILED` instead of leaking upstream.
  - The `@noble/post-quantum` and `@noble/ciphers` cryptographic dependencies are
    pinned to exact versions so a downstream install gets the build that passed the
    NIST vectors.

## 0.2.0

### Minor Changes

- 156cfee: Core correctness fixes for ML-KEM hybrid encryption and base64url decoding.

  - **Fix package description**: drop `SLH-DSA` from the package description, since
    only ML-KEM-768 and ML-DSA-65 are implemented (`SUPPORTED_ALGORITHMS`).
  - **Authenticate the ciphertext header**: the 2-byte header (`FORMAT_VERSION`,
    `headerId`) is now bound as AES-GCM additional authenticated data on both
    encrypt and decrypt, so it is covered by the GCM tag.

    > **Breaking change to the ciphertext format.** This changes the authenticated
    > wire format: ciphertexts produced by `0.1.2` are **not** decryptable by this
    > release, and ciphertexts produced by this release are not decryptable by
    > `0.1.2`. Re-encrypt any data that must remain readable across the upgrade.

  - **Reject non-canonical base64url**: `fromBase64Url` now throws a `TypeError`
    when the trailing bits of the final group are non-zero, instead of silently
    decoding non-canonical input.

## 0.1.2

### Patch Changes

- 82bbac3: Translate all user-facing text to English: CLI command and flag descriptions,
  CLI output (success messages, warnings, audit report, errors), files generated
  by `pqc init`, every typed error message in core, the full public API JSDoc
  (including examples, which feed the generated API reference), package
  descriptions, and both READMEs. Error `code` values are unchanged, so programs
  handling `PqcError` by code are unaffected.

## 0.1.1

### Patch Changes

- c2dbf93: Fix: el export `version` ahora se inyecta en build time desde el `package.json`
  del paquete, en vez de estar hardcodeado. Los bumps de changesets se reflejan
  solos en ESM, CJS y los types.

## 0.1.0

### Minor Changes

- aac9044: Primera release pública: API de cifrado híbrido ML-KEM-768 + AES-256-GCM,
  firmas ML-DSA-65 con context strings, serialización de keys a base64url, y CLI
  con `init`, `keygen` y `audit`.
