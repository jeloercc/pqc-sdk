# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Post-quantum cryptography for JS/TS with safe defaults and zero configuration:
the **X-Wing** hybrid KEM (X25519 + ML-KEM-768) + AES-256-GCM by default,
pure **ML-KEM-768** (FIPS 203) one option away when FIPS scope or size
dominates, **streaming encryption** for files too large to hold in memory, and
**ML-DSA-65** (FIPS 204) for signatures — all validated against the official
NIST ACVP / draft test vectors.

**The API surface is designed to take about 30 minutes to adopt** — that is a
claim about this library's ergonomics, not about migrating an organisation to
post-quantum cryptography. The genuinely hard parts of a PQC migration are key
management, format versioning, key rotation, and interoperability with peers
and other languages, and no SDK removes them. What this one tries to do is
keep the cryptographic decisions few and safe, and be explicit about the
format so the rest is tractable: see
[why PQC now](https://jeloercc.github.io/pqc-sdk/guide/why-pqc) for the threat
that motivates the work, and
[the serialization format](./docs/serialization-format.md) for the byte layout
you would need to interoperate with.

> **Security status, up front.** This SDK has **not** had an independent
> third-party cryptographic audit, and does not claim one; the reviews in
> `docs/` are internal and AI-assisted. As with any JavaScript
> implementation there are **no constant-time guarantees**, and there is **no
> memory zeroization** of secrets, plaintext or key material — JS offers no
> reliable primitive for it. `@noble/post-quantum` has no independent audit
> either (self-audit 04/2026). Read the full threat model in
> [SECURITY.md](./SECURITY.md) before adopting this for anything that matters,
> and [How this is verified](#how-this-is-verified) for what _is_ checked and
> how.

> **Breaking in 0.8.0:** `pqc.keys.generate()` with no arguments now returns
> an **X-Wing** hybrid pair (X25519 + ML-KEM-768), not pure ML-KEM-768 — a
> break in either half still leaves the other standing, which is the same
> reasoning behind TLS's `X25519MLKEM768`, Signal's PQXDH, and the BSI and
> ANSSI recommendations. **JavaScript consumers get no compile-time signal**,
> so read
> [migrating to 0.8.0](https://github.com/jeloercc/pqc-sdk/blob/main/docs/MIGRATION-0.8.md)
> before upgrading. Pure ML-KEM-768 stays first-class and one line away —
> `pqc.keys.generate({ algorithm: 'ml-kem-768' })` — and is the right choice
> when FIPS certification scope or size/speed dominate.

## How this is verified

Read this first if you are evaluating whether to trust this SDK.

- **Official NIST ACVP vectors run in CI** on every commit — ML-KEM-768
  (FIPS 203) and ML-DSA-65 (FIPS 204), plus the X-Wing draft's Appendix C
  vectors. Not a sample: the published vector sets.
- **Five runtimes validated by actual execution, never by inference** — Node,
  Deno, Cloudflare Workers, the Hermes engine, and a **physical Android
  device**. A runtime gets ✅ only after the real roundtrip ran there; anything
  else stays ⏳ and says what is missing.
- **The parser is fuzzed** against arbitrary and hand-picked hostile input,
  asserting it always fails closed rather than returning an attacker-shaped key.
- **Property-based tests** (`fast-check`) assert the invariants over arbitrary
  payloads, including that any single-byte tamper fails closed.
- **Golden wire-format vectors** lock every envelope version, and regenerating
  them requires an acknowledged breaking change — the suite failing is the
  intended tripwire.
- **A mutation matrix** tampers every region of a streaming envelope
  independently — truncation, reorder, duplication, cross-stream splice,
  final-flag games — each asserting the documented error code. The streaming
  envelope binds every chunk to its index and marks the final chunk, adopting
  [age](https://github.com/C2SP/C2SP/blob/main/age.md)'s STREAM construction
  verbatim: see
  [how each chunk is bound](https://jeloercc.github.io/pqc-sdk/guide/streaming-encryption#how-each-chunk-is-bound-to-its-position-and-to-the-stream)
  and [`docs/serialization-format.md` §9.3](./docs/serialization-format.md).

We never implement cryptographic primitives: ML-KEM/ML-DSA come from
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
AES-GCM from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
That means the interesting risk is **not** in the primitives — it is in the
layers this SDK does own: the envelope format, key serialization, nonce
derivation, and fail-closed behaviour on malformed input. Those are what the
following test suites exist to cover, and each one is a file you can read:

| Layer                         | How it is verified                                                                                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Primitive correctness         | Official **NIST ACVP vectors** for ML-KEM-768 and ML-DSA-65, plus the X-Wing draft's Appendix C vectors — [`nist-vectors.test.ts`](./packages/core/src/nist-vectors.test.ts), [`xwing-vectors.test.ts`](./packages/core/src/xwing-vectors.test.ts)                |
| Wire format stability         | **Golden serialization vectors** for every envelope version (v1, v2, streaming), regenerated only behind an acknowledged breaking change — [`src/vectors/`](./packages/core/src/vectors/), [`golden-vectors.test.ts`](./packages/core/src/golden-vectors.test.ts) |
| Parser hostility              | **Fuzzing** of `keys.deserialize` against arbitrary and hand-picked hostile input, asserting it always fails closed — [`deserialize-fuzz.test.ts`](./packages/core/src/deserialize-fuzz.test.ts)                                                                  |
| Roundtrip + tamper invariants | **Property-based tests** (`fast-check`): decrypt(encrypt(x)) === x for arbitrary payloads, and any single-byte tamper fails closed — [`properties.test.ts`](./packages/core/src/properties.test.ts)                                                               |
| Streaming envelope            | **Mutation matrix** tampering every region independently — truncation, reorder, duplication, cross-stream splice, final-flag games — each asserting the documented `PqcError` code — [`stream-mutations.test.ts`](./packages/core/src/stream-mutations.test.ts)   |
| Format specification          | The normative byte layout, so the tests above check an intent rather than the current output — [`docs/serialization-format.md`](./docs/serialization-format.md)                                                                                                   |
| Review                        | Pre-launch findings report ([`docs/AUDIT-2026-06.md`](./docs/AUDIT-2026-06.md)) and a source-level security review ([`docs/SECURITY-REVIEW-2026-06.md`](./docs/SECURITY-REVIEW-2026-06.md))                                                                       |
| Runtime claims                | Node, Deno, Cloudflare Workers, Hermes and a physical React Native device — each ✅ only after the roundtrip actually ran there — [`docs/compatibility.md`](./docs/compatibility.md)                                                                              |

Coverage floor is 90%; the suite currently runs 302 tests across both
packages. Run it yourself with `pnpm turbo run lint test build --force`.

**What these reviews are not.** `docs/AUDIT-2026-06.md` and
`docs/SECURITY-REVIEW-2026-06.md` are internal, AI-assisted reviews. They are
**not** an independent third-party cryptographic audit, and the SDK does not
claim to be audited. `@noble/post-quantum` itself has no independent audit yet
either (self-audit 04/2026).

**Known limitation worth reading before you adopt this: there is no memory
zeroization.** Shared secrets, decrypted plaintext and secret-key bytes are
not wiped after use — JavaScript offers no reliable primitive for it and
`@noble` does not zeroize either, so it is an ecosystem limitation this SDK
cannot fully close. The full threat model, including the absence of
constant-time guarantees, is in [SECURITY.md](./SECURITY.md).

To report a vulnerability, see [SECURITY.md](./SECURITY.md) — please do not
open public issues.

## FIPS 203/204/205 conformance self-assessment

This is the thing that distinguishes this SDK from wrapping
`@noble/post-quantum` directly: `docs/compliance/` carries a clause-by-clause
self-assessment against all three PQC standards this SDK touches. Each
matrix quotes the normative text verbatim, states whether the requirement
applies to this codebase, and assigns one of a closed set of statuses —
`CONFORMING`, `CONFORMING (delegated)`, `NONCONFORMING`, `INDETERMINATE`,
`NOT APPLICABLE` and so on — never a bare pass/fail. A row moves to
`CONFORMING` only on the strength of a named, executed test; every row cites
a file, a line, or a test name as its evidence, never a narrative claim
alone. The assessment follows a findings-before-fixes discipline: the
assessment pass itself changes no code, and remediation lands separately,
referenced by the finding ID.

- [`FIPS-203-MATRIX.md`](./docs/compliance/FIPS-203-MATRIX.md) — 21
  requirements, ML-KEM-768
- [`FIPS-204-MATRIX.md`](./docs/compliance/FIPS-204-MATRIX.md) — 22
  requirements, ML-DSA-44/65/87
- [`FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md) — 21
  requirements registered, all `NOT APPLICABLE` — SLH-DSA is not
  implemented; see [below](#slh-dsa-fips-205-not-implemented-by-scope-decision)

**What was found, and fixed.** Across FIPS 203 and FIPS 204, six findings
were opened as `NONCONFORMING` and closed by an actual code change, each
with an executed regression test cited in the matrix:

- **Floating-point arithmetic** in ML-KEM's `Compress_d` (F203-19) and in
  ML-DSA's `Decompose`/`Power2Round`/`HINT_M` (F204-13) — both standards
  prohibit floating-point arithmetic outright, and JavaScript's `/` is
  always IEEE-754 double division regardless of whether `Math.floor` wraps
  it. Replaced with integer-only BigInt/bit-shift arithmetic, verified
  bit-exact against the code it replaced over the full input domain — all
  36,619 `(q, d)` pairs for `Compress_d`, and all of `Z_q` (8,380,417
  values) for `Power2Round` and both `Decompose` branches.
- **Branch-based implicit-reject selection** in ML-KEM decapsulation
  (F203-18) — which of two candidate shared secrets survived was decided by
  a source-level ternary on the secret reject flag. Replaced with a
  byte-wise arithmetic mask, so every output byte is computed from both
  candidates unconditionally and the branch disappears.
- **Missing zeroization on the ML-DSA verification path** (F204-10) —
  upstream's `internal.verify` had zero `cleanBytes` calls; every decoded
  or recomputed intermediate survived the call. Wrapped in `try`/`finally`
  so all nine intermediates are wiped on every exit, including early
  rejections, while leaving caller-owned buffers (the public key, the
  signature) untouched.
- **RBG failure misattributed as an invalid key** (F203-11) — an entropy
  failure during ML-KEM encapsulation was caught by the same handler as a
  malformed public key, so a host RBG outage was reported to the operator
  as a bad recipient key. Given a dedicated `RBG_FAILURE` error code,
  checked before the generic handler.
- **Wrong-length public key throwing instead of returning `false`**
  (F204-08) — FIPS 204 §3.6.2 requires `ML-DSA.Verify` to _return_ `false`
  on a wrong-length key, not throw; the SDK's own length check ran outside
  the `try` block that would have normalized it. Moved inside.

Three of these (F203-11, F203-18, F203-19) were closed for the standalone
`ml-kem-768` algorithm first, then found to still be open on the **default**
`x-wing` path — a differently-scoped gap in each case, found and closed
separately once asked about. The matrices record both dates. A seventh row,
F203-12 (approved RBG), also left `NONCONFORMING` — but only by
reclassification to `INDETERMINATE`, not by a code fix, and the matrix is
explicit that reclassification is not progress; it is not counted among the
six above.

**What is not claimed.**

- **This is self-assessment, not CMVP validation.** Nothing in this
  repository has been submitted to, or evaluated under, NIST's
  Cryptographic Module Validation Program or Cryptographic Algorithm
  Validation Program. ACVP known-answer vectors passing is assurance
  evidence, not proof of every clause — the floating-point findings above
  are the standing counterexample: those vectors passed for the entire
  time the requirement was breached, because a known-answer test cannot see
  _how_ a bit-identical result was computed.
- **Most `INDETERMINATE` rows depend on the host platform's RBG and cannot
  be closed from inside a library.** FIPS 203/204 require an approved RBG
  under SP 800-90A/B/C with a minimum security strength — a property of
  whatever runs `crypto.getRandomValues` on the deploying platform, which
  this assessment has no visibility into and can no more prove unapproved
  than approved. (One exception: F203-03, also `INDETERMINATE`, is a
  different question — whether X-Wing's API surface is distinguishable from
  actual FIPS 203 coverage — not an RBG matter.)
- **SLH-DSA (FIPS 205) is deliberately unimplemented**, not an unexamined
  gap — see the next section for why.

None of the three matrices' row counts should be read as a score.
`FIPS-203-MATRIX.md` §4.1 and `FIPS-204-MATRIX.md` §4.1 both say so
explicitly, for the same reason the security status above does: an empty
`NONCONFORMING` column is not a compliance claim, and the rows are not of
equal weight.

## SLH-DSA (FIPS 205): not implemented, by scope decision

**ML-DSA-65 is the recommended signature algorithm in this SDK.** SLH-DSA
(FIPS 205, the stateless hash-based signature standard built on SPHINCS+) is
not implemented here, and that is a deliberate scope decision, not an
oversight — recorded with dates and reasoning in
[`docs/compliance/FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md).

- **Signature size.** Per FIPS 205 Table 2, SLH-DSA signatures range from
  7,856 bytes (SLH-DSA-128s, security category 1) to 49,856 bytes
  (SLH-DSA-256f, category 5) — roughly **2.4× to 15× larger** than ML-DSA-65's
  3,309-byte signature.
- **Pure-JS performance cost.** SLH-DSA/SPHINCS+ signing and verification make
  tens of thousands of hash-function invocations per operation (WOTS+ chains,
  a FORS forest, and a hypertree of Merkle trees, all built from repeated
  hashing). ML-DSA's lattice arithmetic has no equivalent per-operation hash
  count. Neither this SDK nor `@noble/post-quantum` accelerates that path with
  native code.
- **Use-case fit.** SLH-DSA exists as a structurally independent hedge against
  a cryptanalytic break in lattice assumptions (the assumptions ML-KEM and
  ML-DSA both rely on) — its target deployments are firmware signing and
  long-lived roots of trust, where the multi-decade signature lifetime
  justifies the size and speed cost. That is not this SDK's target: it is
  built for request/response and file-level encryption and signing in
  ordinary JS/TS services.

**If you have a genuine SLH-DSA requirement** — a long-lived root of trust or
a regulatory mandate specifically naming it — you likely need a
CMVP-validated cryptographic module, not a self-assessed pure-JS library; see
[How this is verified](#how-this-is-verified) for exactly what "self-assessed"
means here. This decision is reopenable: if you have a concrete use case this
SDK's positioning doesn't fit, open an issue and say so.

## Quickstart

```bash
npm install @pqc-sdk/core
```

```ts
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('secret', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('document', signer.secretKey);
const valid = await pqc.verify('document', signature, signer.publicKey);
```

Or bootstrap a whole project with the CLI:

```bash
npx @pqc-sdk/cli init
```

**Full documentation at [jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**:
[5-minute quickstart](https://jeloercc.github.io/pqc-sdk/guide/quickstart),
[hybrid encryption explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption),
[streaming large files](https://jeloercc.github.io/pqc-sdk/guide/streaming-encryption),
[runtime compatibility](https://jeloercc.github.io/pqc-sdk/compatibility) and
[API reference](https://jeloercc.github.io/pqc-sdk/api/).

## Packages

| Package                                                        | What it does                                                                                                                                          |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | The SDK: hybrid encryption, signatures, key handling. Node 20+, Deno, Workers, RN.                                                                    |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init` / `keygen` / `encrypt` / `decrypt` / `audit`: scaffolding, keys, file encryption, and a heuristic (non-exhaustive) scan for legacy crypto. |

## Monorepo structure

```
packages/core    @pqc-sdk/core — the SDK (TypeScript, ESM + CJS)
packages/cli     @pqc-sdk/cli — CLI built on top of core
apps/docs        documentation site (VitePress + typedoc)
examples/        example projects: node, deno, cloudflare-workers, hermes-standalone
docs/            repo source documentation (compatibility)
```

Turborepo + pnpm workspaces. See [CONTRIBUTING.md](./CONTRIBUTING.md) to run
the repo locally.

## License

[MIT](./LICENSE)
