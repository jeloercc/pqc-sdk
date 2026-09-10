---
'@pqc-sdk/core': minor
---

Vendor the ML-KEM primitive and close two FIPS 203 findings

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
