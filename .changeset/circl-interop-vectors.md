---
'@pqc-sdk/core': patch
---

Added cross-implementation interop vectors against Cloudflare's CIRCL (Go) — an independent codebase from the `@noble/post-quantum` family this SDK is built on. ACVP proves this SDK's primitives match NIST's published expected output; it says nothing about whether a second, independently-authored implementation agrees, which is what these vectors actually check.

Three cross-checks, generated once locally (`packages/core/scripts/interop/generate-circl-vectors.mts` + a small Go helper, never run in CI) and committed under `packages/core/src/vectors/interop/`, re-verified against this SDK's own code on every CI run (`src/interop-circl.test.ts`):

- ML-DSA-44/65/87: this SDK signs and CIRCL verifies the raw bytes; CIRCL signs and `pqc.verify` accepts the raw bytes. This closes the real gap ACVP left open — the SDK's own signature _generation_ had never been checked outside the `@noble` family.
- X-Wing: bidirectional shared-secret cross-check (SDK encapsulates → CIRCL decapsulates, and the reverse). X-Wing has no ACVP coverage at all (it's a CFRG draft, not a NIST standard), so this is the first independent evidence for it.
- ML-KEM-768: the same bidirectional check, lowest marginal value since ACVP already covers this algorithm, but cheap once the generator exists.

Also adds a paragraph to `docs/serialization-format.md` stating plainly that the `pqcv1` token and `pqcenc` envelope are this SDK's own encodings, not a wire-interop protocol — only the standard-defined payload inside them (raw key/ciphertext/signature bytes) is interoperable, and that boundary is what these new tests actually check.

Test + docs only — no `packages/*` runtime behavior changed. Adds `tsx` as a devDependency of `@pqc-sdk/core` (needed to run the generator against internal `.ts` source; never part of the published build).
