# PQC SDK — Agent Maintainer Guide

Post-quantum cryptography SDK for JS/TS developers.
Goal: a developer adds PQC encryption to their app in 30 minutes.

---

## Stack

- Strict TypeScript (`exactOptionalPropertyTypes: true`), ESM + CJS dual build
- Monorepo: Turborepo + pnpm workspaces
- Crypto primitives: `@noble/post-quantum` + `@noble/ciphers`, pinned to exact
  versions (bumped deliberately behind the NIST vector tests)
- Algorithms (implemented):
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
  - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
  - X-Wing hybrid KEM (X25519 + ML-KEM-768) — default algorithm
- Algorithms (roadmap, not yet implemented): SLH-DSA (FIPS 205) — deliberate
  scope decision; see `docs/compliance/FIPS-205-MATRIX.md`
- Tests: Vitest with NIST ACVP vectors, 90% minimum coverage floor
- Targets: Node 20+, React Native, Cloudflare Workers, Deno

---

## Packages

| Package               | Purpose                                     | Version                |
| --------------------- | ------------------------------------------- | ---------------------- |
| `@pqc-sdk/core`       | The SDK                                     | `packages/core/`       |
| `@pqc-sdk/cli`        | CLI tool                                    | `packages/cli/`        |
| `@pqc-sdk/mcp-server` | MCP stdio server for AI agents              | `packages/mcp-server/` |
| `@pqc-sdk/langchain`  | LangChain/LangGraph StructuredTool wrappers | `packages/langchain/`  |
| `@pqc-sdk/docs`       | Documentation site                          | `apps/docs/`           |

`core` and `cli` are **linked** in `.changeset/config.json` (they version together).
`mcp-server` and `langchain` version independently.

---

## Hard rules

- **Never implement cryptographic primitives from scratch.** They come from
  `@noble/*`, always. A PR implementing a primitive from scratch gets rejected.
- **Zero-config API: safe defaults always.** The default key type is `x-wing`
  (hybrid); explicit opt-in is required for pure ML-KEM or ML-DSA.
- Every public function must have a JSDoc usage example that actually compiles
  (M3 of the June 2026 audit was exactly this failing).
- Conventional commits: `fix(core): ...`, `feat(cli): ...`, `docs: ...`, etc.
- Every PR touching `packages/*` includes a changeset (`pnpm changeset`).
- All user-facing text MUST be in English: CLI output, error messages, JSDoc,
  READMEs, docs, changesets, code comments, and commit messages. English is
  the project's only public language.

---

## Detailed rules (auto-loaded from `.claude/rules/`)

- `dev-workflow.md` — branching, quality gate, CI discipline
- `release-workflow.md` — changesets flow, version PR, publish & verify
- `crypto-review.md` — findings-first reviews, mutation checks, honest claims

---

## Key commands

```bash
# Full quality gate — run before declaring ANYTHING done
pnpm turbo run lint test build --force

# Individual packages
pnpm --filter @pqc-sdk/core test
pnpm --filter @pqc-sdk/mcp-server lint
pnpm --filter @pqc-sdk/langchain test

# Add a changeset
pnpm changeset

# Format
pnpm format
```

The gate (`lint test build --force`) includes:

- `format:check` (Prettier) — folded into the `lint` turbo task via `//#format:check`
- `eslint . && tsc --noEmit` — per package
- Vitest with coverage
- `tsup` build

---

## How packages relate

```
@pqc-sdk/core          ← crypto SDK, no external runtime deps
  ↑
@pqc-sdk/cli           ← CLI, depends on core
@pqc-sdk/mcp-server    ← MCP server, depends on core + @modelcontextprotocol/sdk
@pqc-sdk/langchain     ← LangChain tools, depends on core + @langchain/core (peer)
@pqc-sdk/docs          ← VitePress site, depends on core (for typedoc)
```

Turbo builds `core` first, then the rest in parallel.

---

## Known interop quirks (important for future maintenance)

### Zod v4 / @langchain/core interop (`packages/langchain`)

`@langchain/core@1.x` was built against Zod v3. The repo root uses Zod v4.
The langchain package bridges this by importing `from 'zod/v3'` (the v3
compatibility subpath) and using an `asToolSchema()` identity function
(widens to `unknown`) to suppress the `@ts-expect-error` at each `schema:`
call site. The `@ts-expect-error` directives are functional — do not remove
them without checking if the underlying Zod v3/v4 type mismatch is resolved.

When TypeScript misinterprets a prose comment like `// @ts-expect-error on
each schema: line...` as a live directive, rename it to `// The ts-expect-error
on each...` to defuse it (TypeScript scans `// @ts-expect-error` literally).

### `exactOptionalPropertyTypes: true`

All packages use strict TS settings. This causes cascading errors when
integrating third-party types not compiled with the same setting. Check
carefully before adding new framework dependencies.

### `eslint` `no-unused-vars` pattern

The root `eslint.config.mjs` does **not** set a custom `argsIgnorePattern`.
The default is `^_` (single underscore prefix). Use `_param` for unused
parameters; if a parameter must be named differently for framework contract
reasons, add `// eslint-disable-next-line @typescript-eslint/no-unused-vars`
on the line immediately above it — no blank line between the comment and the
parameter.

---

## Compliance traceability

Every FIPS 203/204 finding has an ID (F203-xx, F204-xx) and is tracked in:

- `docs/compliance/FIPS-203-MATRIX.md`
- `docs/compliance/FIPS-204-MATRIX.md`
- `docs/compliance/FIPS-205-MATRIX.md`

**Findings-before-fixes discipline:** when opening a new finding, write it to
the matrix first (status `NONCONFORMING`, evidence cited) before touching any
code. The fix lands in a separate PR that references the finding ID.

### Closed findings (do not reopen without new evidence)

| ID      | Description                                          | Status                                         |
| ------- | ---------------------------------------------------- | ---------------------------------------------- |
| F203-19 | Floating-point in `Compress_d`                       | CONFORMING — integer-only bit-shift            |
| F204-13 | Floating-point in `Decompose`/`Power2Round`          | CONFORMING — integer-only BigInt/bit-shift     |
| F203-18 | Branch-based implicit-reject in ML-KEM decapsulation | CONFORMING — arithmetic mask                   |
| F204-10 | Missing zeroization on ML-DSA verify path            | CONFORMING — `try`/`finally` with `cleanBytes` |
| F203-11 | RBG failure misattributed as `INVALID_KEY`           | CONFORMING — dedicated `RBG_FAILURE` code      |
| F204-08 | Wrong-length pk throws instead of returns `false`    | CONFORMING — length check moved inside `try`   |

---

## Test file inventory (core)

When adding a new test, check that it belongs to one of these existing suites
or explain why a new suite is needed:

| File                                                   | What it guards                                              |
| ------------------------------------------------------ | ----------------------------------------------------------- |
| `nist-vectors.test.ts`                                 | NIST ACVP KATs — ML-KEM-512/768/1024, ML-DSA-44/65/87       |
| `xwing-vectors.test.ts`                                | X-Wing draft-10 Appendix C vectors                          |
| `interop-circl.test.ts`                                | Cross-check with CIRCL (Go) for ML-DSA and X-Wing           |
| `golden-vectors.test.ts`                               | Wire format stability — envelope v1                         |
| `golden-vectors-v2.test.ts`                            | Wire format stability — envelope v2 (pqcenc.v2)             |
| `golden-vectors-streaming.test.ts`                     | Wire format stability — streaming envelope                  |
| `properties.test.ts`                                   | Property-based: roundtrip + single-byte tamper (fast-check) |
| `stream-mutations.test.ts`                             | Streaming mutation matrix — every region                    |
| `deserialize-fuzz.test.ts`                             | Parser fuzzing — hostile/arbitrary input                    |
| `key-mutations.test.ts`                                | Key mutation matrix — degenerate and tampered keys          |
| `vendor/ml-kem/__tests__/compress-equivalence.test.ts` | F203-19 regression                                          |
| `vendor/ml-kem/__tests__/implicit-reject.test.ts`      | F203-18 regression                                          |
| `vendor/ml-kem/__tests__/rbg-attribution.test.ts`      | F203-11 regression                                          |
| `vendor/ml-kem/__tests__/fips203-input-checks.test.ts` | F203-05, F203-10 regressions                                |
| `vendor/ml-dsa/__tests__/rounding-equivalence.test.ts` | F204-13 regression                                          |
| `vendor/ml-dsa/__tests__/verify-zeroization.test.ts`   | F204-10 regression                                          |
| `vendor/ml-dsa/__tests__/provider-tripwires.test.ts`   | F204-09, F204-21 regressions                                |

---

## Serialization stability rule

Any change to a serialized layout (key token segments, ciphertext byte layout,
version/header-id values, CLI key-file format) requires in the **same PR**:

1. Update `docs/serialization-format.md`
2. Regenerate golden vectors: `node packages/core/scripts/generate-golden-vectors.mjs`
3. Explicitly acknowledge in the PR description that it is a **breaking change**
   requiring a major version bump

The golden-vector suite failing is the intended tripwire — never "fix" the
fixtures to match new output without the acknowledgment above.

---

## MCP server specifics (`packages/mcp-server`)

- Entry point: `src/index.ts` — starts the MCP stdio transport
- Handlers: `src/handlers.ts` — all tool logic, exported as `handleToolForTest()`
- Use `handleToolForTest()` in tests instead of starting the transport
- The six tools match `MPC/agent-tool-spec.json` exactly
- Build output: `dist/index.js` (ESM only), available as `pqc-mcp` binary

## LangChain package specifics (`packages/langchain`)

- All tools use `from 'zod/v3'` (not `'zod'`) — see interop quirks above
- `dts: false` in `tsup.config.ts` — DTS generation is disabled intentionally
  due to Zod v3/v4 type incompatibility in generated `.d.ts` files
- Individual tool exports + `pqcTools` array bundle
- Tests use `tool.invoke()` — the LangChain invocation path, not raw functions

---

## Agent integration design docs (`MPC/`)

| File                         | Contents                                                      |
| ---------------------------- | ------------------------------------------------------------- |
| `MPC/PLAN.md`                | 3-phase integration roadmap, compatibility matrix, verdicts   |
| `MPC/agent-tool-spec.json`   | OpenAI/Anthropic/Gemini tool-call schema for all 6 operations |
| `MPC/mcp-server-spec.md`     | MCP server design — transport, secrets, error handling        |
| `MPC/langchain-tool-spec.md` | LangChain StructuredTool wrapper spec                         |
| `MPC/a2a-protocol.md`        | Agent-to-Agent secure channel protocol (ML-KEM + ML-DSA)      |
| `MPC/pr-bodies.md`           | Ready-to-paste GitHub PR bodies                               |

---

## Release flow

1. Every PR touching `packages/*` needs a changeset: `pnpm changeset`
2. `core` and `cli` are linked — they bump together
3. On merge to `main`, the changesets bot opens a version PR
4. Merging the version PR publishes to npm (with OIDC provenance)
5. After release: verify with `npm view @pqc-sdk/core version`

The `action_required` status on `changeset-release/main` workflow runs is
**expected** — it is GitHub's loop prevention, not a broken build. Do not
rerun it.

---

## What NOT to do

- **Never commit directly to `main`** — everything via PR
- **Never rerun a CI failure without diagnosing it first** — read the logs
- **Never "fix" golden vector tests by regenerating fixtures** without the
  breaking-change acknowledgment and a `docs/serialization-format.md` update
- **Never print key material, shared secrets, or plaintext** in errors, logs,
  test names, docs, commits, or CI output
- **Never overstate runtime support** — a runtime is ✅ only after the real
  roundtrip ran on that actual runtime
- **Never add a `@ts-expect-error` without a comment explaining exactly why**
  it is needed and what upstream change would remove it
