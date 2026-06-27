# PQC SDK

Post-quantum cryptography SDK for JS/TS developers.
Goal: a developer adds PQC encryption to their app in 30 minutes.

## Stack

- Strict TypeScript, ESM + CJS dual build
- Monorepo with Turborepo + pnpm workspaces
- Cryptographic base: liboqs (via @open-quantum-safe or noble where applicable)
- Algorithms (implemented): ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204)
- Algorithms (roadmap, not yet implemented): SLH-DSA (FIPS 205)
- Tests: Vitest with NIST test vectors, 90% minimum coverage
- Targets: Node 20+, React Native, Cloudflare Workers, Deno

## Rules

- Never implement cryptographic primitives from scratch
- Zero-config API: safe defaults always
- Every public function must have JSDoc with a usage example
- Conventional commits
- All user-facing text MUST be in English: CLI output, error messages, JSDoc,
  READMEs, docs, changesets, code comments, and commit messages. English is
  the project's only public language.
