# PQC SDK

Post-quantum cryptography SDK for JS/TS developers.
Goal: a developer adds PQC encryption to their app in 30 minutes.

## Stack

- Strict TypeScript, ESM + CJS dual build
- Monorepo: Turborepo + pnpm workspaces (`packages/core`, `packages/cli`, `apps/docs`)
- Crypto primitives: `@noble/post-quantum` + `@noble/ciphers`, pinned to exact
  versions (bumped deliberately behind the NIST vector tests)
- Algorithms (implemented): ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204),
  X-Wing hybrid KEM (X25519 + ML-KEM-768, opt-in, `pqcenc.v2`)
- Algorithms (roadmap, not yet implemented): SLH-DSA (FIPS 205)
- Tests: Vitest with NIST ACVP vectors, 90% minimum coverage
- Targets: Node 20+, React Native, Cloudflare Workers, Deno

## Hard rules

- Never implement cryptographic primitives from scratch
- Zero-config API: safe defaults always
- Every public function must have a JSDoc usage example that actually
  compiles (M3 of the June 2026 audit was exactly this failing)
- Conventional commits
- Every PR touching `packages/*` includes a changeset
- All user-facing text MUST be in English: CLI output, error messages, JSDoc,
  READMEs, docs, changesets, code comments, and commit messages. English is
  the project's only public language.

## Detailed rules (auto-loaded from `.claude/rules/`)

- `dev-workflow.md` — branching, quality gate, CI discipline
- `release-workflow.md` — changesets flow, version PR, publish & verify
- `crypto-review.md` — findings-first reviews, mutation checks, honest claims

## Key commands

- Quality gate (run before declaring anything done):
  `pnpm turbo run lint test build --force`
- Add a changeset: `pnpm changeset`
