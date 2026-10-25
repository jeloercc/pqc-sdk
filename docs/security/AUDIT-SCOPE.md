# Audit scope — `@pqc-sdk/core`

Scope for an independent security audit of the cryptographic core of
pqc-sdk. Threats, assets and assumptions are in
[`THREAT-MODEL.md`](./THREAT-MODEL.md).

## 1. Target

| Item                  | Value                                                                                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Package               | `@pqc-sdk/core` **0.11.2** (npm `latest` on 2026-10-25)                                                                                               |
| Git tag               | `@pqc-sdk/core@0.11.2`                                                                                                                                |
| Commit                | `449d885ec9351ceff983b85b285daba6c8d90c0a` (2026-10-02, "chore: version packages (#108)")                                                             |
| Provenance            | The npm SLSA provenance of 0.11.2 names `github.com/jeloercc/pqc-sdk`, `refs/heads/main`, `gitCommit` `449d885ec9351ceff983b85b285daba6c8d90c0a`      |
| npm tarball integrity | `sha512-owOF8kzZQI4LILrQXHWZ2i0E4iesLVRFYkUjsudt0YsidMY5iY2/8EF5ljKYccajzNnsgGJ9RQvDZOUEGWxQmQ==` (shasum `01d3efba61c9638366a276df0bf8e53868400e18`) |
| Repository            | https://github.com/jeloercc/pqc-sdk                                                                                                                   |

### 1.1 Why the audited commit is not `main`

The audit targets what users install: the latest **published** release,
0.11.2, built from `449d885` (provenance above). `main` was at
`715221290f150171d131e0abd1ed7dc9706dfa3b` (2026-10-03, #111) when this
document was written; no new `@pqc-sdk/core` version has been released
since 0.11.2 because nothing after it changed core's published code.

Three commits landed on `main` after the release:

```
$ git log --oneline 449d885..7152212
7152212 ci: pin runners to ubuntu-24.04; scope test's own-build dependency (#111)
a8217c3 fix(ci): build each package's dist once per turbo run (#110)
e3fa99c feat(evals): open-model eval harness for @pqc-sdk/langchain (#109)
```

Only one of them touches `packages/core/src`, and only test files:

```
$ git log --oneline 449d885..7152212 -- packages/core/src
a8217c3 fix(ci): build each package's dist once per turbo run (#110)

$ git diff --stat 449d885 7152212 -- packages/core/src packages/core/package.json packages/core/tsup.config.ts
 packages/core/src/interop-circl.test.ts                              | 5 ++++-
 packages/core/src/key-mutations.test.ts                              | 5 ++++-
 packages/core/src/properties.test.ts                                 | 5 ++++-
 packages/core/src/vendor/ml-dsa/__tests__/provider-tripwires.test.ts | 5 ++++-
 4 files changed, 16 insertions(+), 4 deletions(-)
```

Those four edits raise the vitest timeout of CPU-bound test suites; no
iteration count or assertion changed. #110 carried an empty changeset, so
the release workflow on its merge commit published nothing (run
`37096732953`: "All changesets are empty; not creating PR"). Production
source, `package.json` and the build config of `@pqc-sdk/core` are
therefore identical at `449d885` and `7152212`.

The audit covers the TypeScript source at `449d885`. Whether the published
`dist/` is a reproducible build of that source has **not** been verified.

## 2. In scope

Counts by `cloc` 1.96 (`npx cloc@2 --by-file packages/core/src`, excluding
tests, benchmarks, `stream-test-helpers.ts` and the `vectors/` JSON) at
commit `715221290f150171d131e0abd1ed7dc9706dfa3b`; `blank + comment + code`
equals `wc -l` for every file.

### 2.1 Priority 1 — primitives and constructions

| File                                           | Code | Comment | Blank | Total | What it is                                                                                             |
| ---------------------------------------------- | ---: | ------: | ----: | ----: | ------------------------------------------------------------------------------------------------------ |
| `packages/core/src/vendor/ml-kem/ml-kem.ts`    |  497 |     327 |    27 |   851 | ML-KEM-512/768/1024 (FIPS 203), vendored from `@noble/post-quantum` 0.7.1 **with modifications**       |
| `packages/core/src/vendor/ml-kem/_crystals.ts` |  174 |     147 |    12 |   333 | Shared CRYSTALS arithmetic (NTT, sampling), vendored with modifications                                |
| `packages/core/src/vendor/ml-kem/utils.ts`     |  384 |     423 |    27 |   834 | Shared helpers incl. `cleanBytes`, randomness sampling, `RbgFailureError`; vendored with modifications |
| `packages/core/src/vendor/ml-dsa/ml-dsa.ts`    |  683 |     289 |    35 |  1007 | ML-DSA-44/65/87 (FIPS 204), vendored with modifications                                                |
| `packages/core/src/x-wing.ts`                  |   24 |      73 |     4 |   101 | X-Wing (draft-connolly-cfrg-xwing-kem-10) from vendored ML-KEM-768 + X25519 + upstream `combineKEMS`   |
| `packages/core/src/encrypt.ts`                 |   73 |      79 |    14 |   166 | One-shot hybrid envelope: KEM + AES-256-GCM, header as AAD                                             |
| `packages/core/src/sign.ts`                    |   86 |      74 |     8 |   168 | ML-DSA sign/verify wrappers, hedged `rnd`, context string, F204-08 behavior                            |
| `packages/core/src/stream.ts`                  |  266 |     183 |    33 |   482 | Streaming envelope (age STREAM nonce, chunk framing, truncation rules)                                 |
| `packages/core/src/keys.ts`                    |  116 |      95 |     8 |   219 | Key generation and `pqcv1` token (de)serialization                                                     |
| **Subtotal**                                   | 2303 |    1690 |   168 |  4161 |                                                                                                        |

The modifications to the vendored files are listed in each file's header
and in `packages/core/src/vendor/ml-kem/NOTICE.md`, which also records the
sha256 of each pristine upstream copy; `vendor-drift-check.yml` checks
those digests against upstream at the pinned version.

### 2.2 Priority 2 — supporting code on every path

| File                              | Code | Comment | Blank | Total | What it is                                                                                         |
| --------------------------------- | ---: | ------: | ----: | ----: | -------------------------------------------------------------------------------------------------- |
| `packages/core/src/algorithms.ts` |  190 |      83 |    15 |   288 | Algorithm registry, key-shape checks (`requireKey`), encapsulation dispatch, `RBG_FAILURE` mapping |
| `packages/core/src/stream-web.ts` |   56 |      59 |     5 |   120 | Web Streams adapters over `stream.ts`                                                              |
| `packages/core/src/index.ts`      |   67 |      78 |     8 |   153 | Public API surface (`pqc` object, exports)                                                         |
| `packages/core/src/base64url.ts`  |   40 |       5 |     3 |    48 | base64url codec used by key tokens                                                                 |
| `packages/core/src/errors.ts`     |   24 |      38 |     3 |    65 | `PqcError` and its codes                                                                           |
| `packages/core/src/types.ts`      |   19 |      20 |     8 |    47 | Public types                                                                                       |
| **Subtotal**                      |  396 |     283 |    42 |   721 |                                                                                                    |

**Total in scope: 2,699 lines of code** (1,973 comment, 210 blank; 4,882
physical lines) in 15 files.

### 2.3 Upstream code executed unmodified (in scope as integration)

`@noble/post-quantum` 0.7.1 is still a runtime dependency. Besides type
imports, two places call it unmodified:

| Upstream file (`@noble/post-quantum@0.7.1/src/`)         | Code | Total | Used by                                                   |
| -------------------------------------------------------- | ---: | ----: | --------------------------------------------------------- |
| `hybrid.ts` — `combineKEMS`, `expandSeedXof`, `_ecdhKem` |  575 |   967 | `x-wing.ts` (X-Wing combiner, seed expansion, X25519 KEM) |
| `utils.ts` — `randomBytes`                               |  384 |   815 | `encrypt.ts` (AES-GCM nonce)                              |

Auditing how these are used (parameters, the X-Wing label and combiner
input order against the draft) is in scope; finding defects inside them
is upstream's (SECURITY.md, "Scope"). AES-256-GCM (`@noble/ciphers` 2.2.0),
X25519 (`@noble/curves` 2.4.0) and SHA-3/SHAKE (`@noble/hashes` 2.4.0) are
used as published and are likewise out of scope except for their use.

## 3. Out of scope

| Path                                                                            | Code (non-test) | Why                                                                                              |
| ------------------------------------------------------------------------------- | --------------: | ------------------------------------------------------------------------------------------------ |
| `packages/cli/`                                                                 |             763 | Application on top of core (key files, file encryption, legacy-crypto scan)                      |
| `packages/mcp-server/`                                                          |             711 | MCP agent server; keystore and model-context threats are separate (GHSA-p2f3-84pf-p4jv)          |
| `packages/langchain/`                                                           |             315 | LangChain tool wrappers; secret keys move only through application callbacks                     |
| Tests: `packages/core/src/**/*.test.ts`, `__tests__/`, `stream-test-helpers.ts` |           3,255 | Evidence, not target; reading them is encouraged (inventory in CLAUDE.md, "Test file inventory") |
| `packages/core/src/vectors/` (JSON)                                             |               — | Test vectors (NIST ACVP, X-Wing draft-10, CIRCL interop, golden wire formats)                    |
| `packages/core/scripts/`, `packages/core/bench/`                                |           1,768 | Tooling: vector generation, drift checks, benchmarks                                             |
| `apps/docs/`, `examples/`, `evals/`                                             |               — | Documentation site, runtime examples, open-model eval harness                                    |
| `.github/workflows/`                                                            |               — | CI/CD — see `THREAT-MODEL.md` §3.4 for what the pipeline does and does not guarantee             |
| `@noble/*` internals                                                            |               — | Report upstream (see §2.3)                                                                       |

Counts for the out-of-scope packages are `cloc` code lines of their `src/`
excluding `*.test.ts`. Test code: cli 778, mcp-server 742, langchain 336.

## 4. Compliance and prior review material

- FIPS 203 (ML-KEM) conformance matrix: [`docs/compliance/FIPS-203-MATRIX.md`](../compliance/FIPS-203-MATRIX.md)
- FIPS 204 (ML-DSA) conformance matrix: [`docs/compliance/FIPS-204-MATRIX.md`](../compliance/FIPS-204-MATRIX.md)
- FIPS 205 (SLH-DSA) — not implemented, decision record: [`docs/compliance/FIPS-205-MATRIX.md`](../compliance/FIPS-205-MATRIX.md)
- Wire formats and error contract: [`docs/serialization-format.md`](../serialization-format.md)
- Security policy, randomness source, dependency policy: [`SECURITY.md`](../../SECURITY.md)
- Earlier internal reviews (AI-assisted, **not** independent):
  [`docs/AUDIT-2026-06.md`](../AUDIT-2026-06.md),
  [`docs/AUDIT-2026-09.md`](../AUDIT-2026-09.md),
  [`docs/SECURITY-REVIEW-2026-06.md`](../SECURITY-REVIEW-2026-06.md)

## 5. Known items to look at

Found while preparing this document. Items 2 and 3 are documentation
errors fixed in the same PR as this document. Item 1 was fixed in a later
commit, after the audited release (details in the item); the others are
reported for the audit and left unchanged.

1. **`RBG_FAILURE` is not uniform — resolved after the audited release in
   [#113](https://github.com/jeloercc/pqc-sdk/pull/113).** In 0.11.2, key generation, encapsulation and signing
   map a platform RNG failure to `PqcError('RBG_FAILURE')`, but the
   one-shot AES-GCM nonce in `encrypt.ts` (`randomBytes(NONCE_LENGTH)`, from
   `@noble/post-quantum/utils.js`) does not, so a failure there propagates
   the host's raw error; it still fails closed. [#113](https://github.com/jeloercc/pqc-sdk/pull/113) draws the
   nonce through `sampleRandomness` and maps the failure to `RBG_FAILURE`,
   with the same single 12-byte draw after encapsulation, so ciphertext
   bytes are unchanged. It ships in the next `@pqc-sdk/core` patch release;
   the audited 0.11.2 still has the old behavior. Regression tests:
   `vendor/ml-kem/__tests__/rbg-attribution.test.ts`.
2. **Error-contract table — resolved in the same PR as this document.**
   `docs/serialization-format.md` §6 listed valid version/header bytes as
   `{0x01, 0x02}` and had no streaming rows. It now lists all four one-shot
   pairs `(0x01..0x04, 0x01..0x04)` and all four streaming pairs
   `(0x03..0x06, 0x01..0x04)`, taken from `algorithms.ts`
   (`envelopeVersion` / `headerId`) and `stream.ts`
   (`STREAM_ENVELOPE_VERSION`).
3. **Zeroization count — resolved in the same PR as this document.**
   SECURITY.md cited 41 `cleanBytes` call sites in `vendor/`; the 41 matches
   included the function definition and a JSDoc example. It now says 39 and
   carries the command that reproduces the number.
4. **Duplicate `@noble/ciphers`.** Core pins `@noble/ciphers 2.2.0`, while
   `@noble/post-quantum 0.7.1` depends on `2.4.0`, so both are installed.
   Core's AES-GCM comes from 2.2.0 (`encrypt.ts`, `stream.ts`).
5. **`main` has no branch protection or rulesets** (checked 2026-10-25);
   see THREAT-MODEL §3.4.
6. **No header or cross-algorithm tests for `ml-kem-512` / `ml-kem-1024`
   ciphertexts.** The streaming mutation suite runs only for `ml-kem-768`
   and `x-wing` (`stream-mutations.test.ts`, `ALGORITHMS`), and the one-shot
   header tests cover v1/v2. The 512/1024 envelopes go through the same
   checks, but nothing locks their `INVALID_CIPHERTEXT` behavior.
7. **Stale JSDoc in `stream.ts`.** The `decryptStream` comment (lines
   271–275) names only streaming versions `0x03` (ml-kem-768) and `0x04`
   (x-wing); `0x05` (ml-kem-512) and `0x06` (ml-kem-1024) also exist
   (`STREAM_ENVELOPE_VERSION`, lines 26–31). Comment only; behavior is
   correct.

## 6. How to reproduce the numbers

```bash
git checkout 449d885ec9351ceff983b85b285daba6c8d90c0a
pnpm install --frozen-lockfile
npx cloc@2 --by-file packages/core/src --exclude-dir=vectors,__tests__ \
  --not-match-f='(\.test\.ts|\.bench\.ts|stream-test-helpers\.ts)$' \
  --include-lang=TypeScript
pnpm turbo run lint test build --force      # full quality gate
npm audit signatures                        # in a project that installs @pqc-sdk/core@0.11.2
```
