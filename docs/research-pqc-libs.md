# Research: PQC libraries for JS/TS (June 2026)

Comparison of candidate cryptographic foundations for the SDK.
Conclusion: **use `@noble/post-quantum` as the base**.

## Comparison

| Criterion          | @noble/post-quantum                        | mlkem (dajiaji)                         | @oqs/liboqs-js (WASM)                                                       | liboqs-node (native)   |
| ------------------ | ------------------------------------------ | --------------------------------------- | --------------------------------------------------------------------------- | ---------------------- |
| Latest release     | v0.6.1 · Apr 2026                          | v2.7.0 · Mar 2026                       | v0.15.1 · Feb 2026                                                          | v0.1.0 · 2022 (dead)   |
| Downloads/week     | ~122,000                                   | ~7,800                                  | ~650                                                                        | ~280                   |
| ML-KEM (FIPS 203)  | ✅ final                                   | ✅ final                                | ✅ final                                                                    | Pre-standard Kyber     |
| ML-DSA (FIPS 204)  | ✅ final                                   | ❌ KEM only                             | ✅ final                                                                    | Pre-standard Dilithium |
| SLH-DSA (FIPS 205) | ✅ final                                   | ❌                                      | ✅ final                                                                    | Pre-standard SPHINCS+  |
| Cloudflare Workers | ✅                                         | ✅                                      | Possible, undocumented                                                      | ❌ (native addon)      |
| React Native       | ✅ (getRandomValues polyfill)              | Likely (pure TS)                        | ❌ (WASM on Hermes)                                                         | ❌                     |
| Deno / Bun         | ✅ (JSR)                                   | ✅                                      | ✅                                                                          | ❌                     |
| Bundle             | ~16 KB gzip (everything)                   | Small (pure TS, tree-shakable)          | 80–500 KB WASM per algorithm                                                | N/A                    |
| Dependencies       | Only @noble/\* (same author)               | Zero                                    | Compiled liboqs                                                             | node-pre-gyp, etc.     |
| Audit              | Self-audit 0.6.1; no independent audit yet | No audit; passes KATs (NIST, C2SP/CCTV) | Inherits liboqs (well reviewed; "experimental, not for production" per OQS) | —                      |

## Notes per library

### @noble/post-quantum (recommended)

- Covers exactly the 3 algorithms in CLAUDE.md (ML-KEM-768, ML-DSA-65,
  SLH-DSA) with the final FIPS, in a single auditable TypeScript package.
- Runs on every project target: Node 20+, Workers, Deno and React Native (the
  latter needs a `crypto.getRandomValues` polyfill, e.g.
  `react-native-get-random-values`).
- Caveats to document in the SDK: no guaranteed constant-time protections (a
  limitation of all JIT-compiled JS) and no independent audit yet (self-audit
  in 0.6.1, Apr 2026). The included Falcon is Round 3, not final FN-DSA — do
  not use it.
- Design the SDK's provider layer (`packages/core/src/providers/`) so the
  backend can be swapped if WASM/native becomes worthwhile on some runtime
  later.

### mlkem / crystals-kyber-js (dajiaji)

- Excellent pure-TS ML-KEM implementation (claims ~5x faster than the
  reference, passes NIST, C2SP/CCTV and pq-crystals KATs), but **KEM only**:
  it would force mixing authors/styles for ML-DSA and SLH-DSA.
- A candidate as an alternative ML-KEM backend if benchmarks justify it.

### WASM alternatives (@oqs/liboqs-js)

- It is the official successor: openforge-sh/liboqs-node was archived in Feb
  2026 and adopted by Open Quantum Safe as `@oqs/liboqs-js`. WASM per
  algorithm (80–500 KB each), requires Node 22+ for SIMD.
- Pros: inherits liboqs maturity (v0.15, active). Cons: 5–30x larger bundle,
  no React Native, minimal adoption (~650 downloads/week), and OQS warns that
  liboqs is for experimentation.
- Re-evaluate if a formal audit appears or if native server performance is
  needed.

### liboqs-node (TapuCosmo and forks)

- The original is dead (v0.1.0, 2022, pre-standard algorithms). The
  @skairipaapps fork had activity until Jun 2025. Native addon: incompatible
  with Workers/RN/Deno. **Discarded.**

## Decision

`@noble/post-quantum` as the base dependency of `@pqc-sdk/core`:

1. The only maintained package covering final FIPS 203 + 204 + 205.
2. The only one compatible with the project's 4 targets (Node, Workers, RN,
   Deno).
3. ~16 KB bundle vs 80–500 KB per algorithm in WASM.
4. Very active maintenance (Apr 2026 release) and dominant adoption
   (~122k/week).
5. Satisfies the "never implement primitives from scratch" rule by delegating
   to an implementation with KATs and a track record (the noble ecosystem).

Sources: github.com/paulmillr/noble-post-quantum · github.com/dajiaji/crystals-kyber-js ·
github.com/openforge-sh/liboqs-node (archived → @oqs/liboqs-js) · github.com/TapuCosmo/liboqs-node ·
openquantumsafe.org/liboqs · registry.npmjs.org / api.npmjs.org (versions and downloads, 2026-06-11)
