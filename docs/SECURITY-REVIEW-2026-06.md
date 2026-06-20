# Security review — @pqc-sdk

> **This is an internal, AI-assisted security review of the `@pqc-sdk` source code. It is _not_ an independent third-party cryptographic audit, and it does not certify the library as audited.** It complements, but does not replace, a professional audit or formal cryptanalysis. It is published in the spirit of transparency, consistent with the limitations already documented in [`SECURITY.md`](../SECURITY.md).

**Date:** June 2026
**Reviewed:** `@pqc-sdk/core` and `@pqc-sdk/cli`, immediately prior to the `0.2.0` release
**Method:** manual source review and reasoning — no formal verification, fuzzing, or side-channel analysis

## Scope

In scope:

- The `@pqc-sdk/core` cryptographic construction: KEM-DEM hybrid encryption (ML-KEM-768 / FIPS 203 + AES-256-GCM) and ML-DSA-65 (FIPS 204) signatures.
- Key generation, serialization/deserialization, and length validation.
- The `@pqc-sdk/cli` commands (`init`, `keygen`, `audit`) and key-file handling.
- Build, test, and release configuration (CI, Changesets, npm provenance).

Out of scope:

- Formal cryptanalysis of ML-KEM and ML-DSA themselves.
- The upstream `@noble/post-quantum` implementation, which has no independent audit of its own (see `SECURITY.md`).
- Constant-time guarantees and side-channel resistance in JavaScript.

## Findings

All findings below were addressed in `0.2.0`. None described an actively exploitable weakness at the time of review; the integrity- and accuracy-related items were resolved before this document was published. Exploit-level detail is intentionally omitted.

| #   | Finding                                                                                  | Severity                  | Status                                                                                  |
| --- | ---------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------------------- |
| 1   | The npm package description advertised SLH-DSA, which is not implemented.                | Medium (accuracy)         | Resolved in 0.2.0 — description corrected.                                              |
| 2   | "Hybrid" could be read by a post-quantum audience as classical+PQC; the SDK is PQC-only. | Medium (docs/positioning) | Resolved in 0.2.0 — terminology clarified; a classical+PQC hybrid added to the roadmap. |
| 3   | The 2-byte ciphertext header was not bound into the AEAD.                                | Low (defense-in-depth)    | Resolved in 0.2.0 — header bound as AES-GCM AAD.                                        |
| 4   | The base64url decoder accepted non-canonical input.                                      | Low (correctness)         | Resolved in 0.2.0 — non-canonical input is now rejected.                                |
| 5   | `keygen` produced fixed, surprising filenames with no override.                          | Low (UX)                  | Resolved in 0.2.0 — `--name` flag added, validated against path separators and `..`.    |
| 6   | `audit` was presented as authoritative and read files without a size bound.              | Low (UX / resource use)   | Resolved in 0.2.0 — reframed as a heuristic; 1 MiB per-file cap added.                  |

Note: binding the header as AAD (finding 3) changed the authenticated ciphertext format — ciphertexts produced by `0.2.0` are not interchangeable with `0.1.x`. See the `0.2.0` changelog.

## Checked and found sound

- The KEM-DEM construction is appropriate: a fresh ML-KEM-768 encapsulation per message yields a unique 32-byte shared secret used directly as the AES-256-GCM key, so each message has a unique key.
- ML-KEM's implicit rejection is handled correctly — integrity rests on the AEAD tag rather than on distinguishing decapsulation outcomes.
- Key algorithm/use/length validation is centralized and applied consistently before any operation.
- Secret-key files are written with mode `0600` plus an explicit `chmod`, so the process umask cannot widen them.
- Randomness is sourced from the platform CSPRNG via `@noble/post-quantum`.
- NIST ACVP test vectors (FIPS 203/204) run in CI and validate key generation and decapsulation against expected values — substantive, not vacuous.
- Runtime dependencies are declared correctly; test-only dependencies are not shipped.
- Package versions are injected at build time from `package.json` (safely serialized), with no hardcoded version strings.
- Packages are published to npm with provenance via OIDC trusted publishing, recorded in the sigstore transparency log.

## Residual risks and known limitations

- `@noble/post-quantum` has no independent audit, and there are no strict constant-time guarantees in JavaScript. (Already disclosed in `SECURITY.md`.)
- ML-KEM and ML-DSA are relatively new standards. The SDK is currently PQC-only; a classical+PQC hybrid (X25519 + ML-KEM-768, following an established combiner) is on the roadmap as defense-in-depth during the migration period.
- This review is internal and AI-assisted. It is not a substitute for an independent professional audit or for formal cryptanalysis.

## Reporting

Suspected vulnerabilities should be reported privately as described in [`SECURITY.md`](../SECURITY.md).
