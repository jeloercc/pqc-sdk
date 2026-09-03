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
- **Combiner discipline.** Hybrid constructions use an established,
  fully-specified combiner (e.g. X-Wing) verbatim; never add extra KDF
  layers on top of a spec-defined combiner, and never design secret-mixing.
  Spec citations must be verified against the actual draft text before
  committing them.
- **Honest compatibility claims.** A runtime gets ✅ in
  `docs/compatibility.md` only after the real roundtrip has executed on that
  actual runtime (physical device, real worker, real engine). Harness builds,
  clean bundling, or engine-only shims are ⏳ and the doc must say exactly
  what is still missing. Never overstate implemented algorithms or validated
  targets (audit findings M2 and the RN ⏳ row exist because of this rule).
- **Verify runtime feature assumptions on the actual engine.** Before an
  example, a doc, or a compatibility claim depends on a language or host
  feature being present — `Symbol.asyncIterator`, async generators,
  `for await...of`, Web Streams (`TransformStream`/`ReadableStream`),
  `TextDecoder`, `crypto.getRandomValues` — run it on that engine and record
  the result. "It is part of the language, not a host API" is not evidence;
  neither is a clean type-check or a clean bundle. Hermes is the standing
  example in both directions: it implements no part of ES2018 async
  iteration (RN's own `hermesc` rejects `async function*` outright, so Metro
  must downlevel it, and Babel's transpiled generators key their iterator on
  the string `"@@asyncIterator"` rather than the missing symbol — breaking
  any explicit `obj[Symbol.asyncIterator]()` lookup), and it provides no Web
  Streams at all. Both were found by executing the engine, and neither is
  visible from types or bundling. Where a gap is permanent rather than
  pending, say so in `docs/compatibility.md` as a known limitation with the
  supported alternative — distinct from a ⏳, which means "not yet run".
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
