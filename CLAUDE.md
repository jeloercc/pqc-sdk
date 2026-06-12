# PQC SDK

SDK de criptografía post-cuántica para developers JS/TS.
Objetivo: que un developer agregue cifrado PQC a su app en 30 minutos.

## Stack

- TypeScript strict, ESM + CJS dual build
- Monorepo con Turborepo + pnpm workspaces
- Base criptográfica: liboqs (vía @open-quantum-safe o noble si aplica)
- Algoritmos: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205)
- Tests: Vitest con test vectors NIST, coverage mínimo 90%
- Targets: Node 20+, React Native, Cloudflare Workers, Deno

## Reglas

- Nunca implementar primitivas criptográficas desde cero
- API zero-config: defaults seguros siempre
- Cada función pública debe tener JSDoc con ejemplo de uso
- Conventional commits
- All user-facing text MUST be in English: CLI output, error messages, JSDoc,
  READMEs, docs, changesets, code comments, and commit messages. English is
  the project's only public language.
