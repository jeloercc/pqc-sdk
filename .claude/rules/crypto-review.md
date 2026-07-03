# Crypto review discipline

- **Findings before fixes.** Audits and security reviews produce a findings
  report FIRST (severity, location, evidence — see `docs/AUDIT-2026-06.md`
  for the format), with nothing changed in the same pass. Remediation lands
  afterwards as separate, reviewable PRs that reference the finding IDs.
- **Mutation-check test suites.** A test guarding a cryptographic property
  must fail when the property is broken: tamper every region independently
  (header, KEM ciphertext, nonce, sealed payload, signature bytes, serialized
  key segments) and assert fail-closed behavior with the documented
  `PqcError` code — never a raw upstream `@noble` error leaking through.
- **Honest compatibility claims.** A runtime gets ✅ in
  `docs/compatibility.md` only after the real roundtrip has executed on that
  actual runtime (physical device, real worker, real engine). Harness builds,
  clean bundling, or engine-only shims are ⏳ and the doc must say exactly
  what is still missing. Never overstate implemented algorithms or validated
  targets (audit findings M2 and the RN ⏳ row exist because of this rule).
- **No secrets in output.** Never print, log, or embed key material, shared
  secrets, or plaintext in error messages, test names, docs, commits, or CI
  logs. Errors carry only lengths, algorithm names, and key use. This applies
  to review artifacts and session output too.
- **Serialization stability.** Any change touching a serialized layout (key
  token segments, ciphertext byte layout, version/header-id values, CLI
  key-file format) requires, in the same PR: updating
  `docs/serialization-format.md`, regenerating the golden vectors
  (`packages/core/scripts/generate-golden-vectors.mjs`), and an explicit
  acknowledgment in the PR description that it is a breaking change requiring
  a **major version bump**. The golden-vector suite failing is the intended
  tripwire — never "fix" those tests or fixtures to match new output without
  that acknowledgment.
