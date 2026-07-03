# @pqc-sdk/core

## 0.3.9

### Patch Changes

- 459b64f: Lock the serialization formats across versions: normative spec in `docs/serialization-format.md` (key token layout, hybrid ciphertext byte layout, signature encoding, CLI key files, error contract, forward-compatibility rules) plus golden-vector tests generated with the published 0.3.8 — serialized keys for both algorithms and uses, a complete ciphertext, and a signature that every future version must keep deserializing and using correctly. Unknown version markers (`pqcv2` tokens, unknown ciphertext version byte) are pinned to fail closed with clear `PqcError` codes.

## 0.3.8

### Patch Changes

- 184516d: Add performance benchmarks for the five core operations (ML-KEM-768 keygen/encrypt/decrypt, ML-DSA-65 keygen/sign/verify) with automatic regression detection in CI: every PR reports the measured numbers and fails when any operation exceeds 2.5x the committed baseline. `generateKeyPairFromSeed` now returns the narrow `KeyPair<A>` type inferred from its algorithm argument (type-level only, no runtime change).

## 0.3.7

### Patch Changes

- b429873: Docs only: mark React Native as validated in the compatibility matrix. The full ML-KEM-768 encrypt/decrypt and ML-DSA-65 sign/verify roundtrip ran on a physical Android device via Expo Go (SDK 54) with genuine native entropy from `react-native-get-random-values`.

## 0.3.6

### Patch Changes

- bd18bea: Roll `examples/react-native-expo` back to Expo SDK 54 (from SDK 56). The Expo
  Go client actually installed on the test device is v54.0.8, which only
  supports SDK 54 — Play Store rollout of newer Expo Go builds lags per-device,
  so the example tracks what is installable on the test hardware, not the
  latest SDK. `expo install expo@^54.0.0 --fix` realigned `react-native`
  (0.85.3 → 0.81.5), `expo-status-bar`, `react`, and `typescript`; the
  `expo-status-bar` config-plugin entry was removed from `app.json` because the
  package does not ship a config plugin on SDK 54. `expo-doctor` reports 18/18
  checks passing and `npx expo export --platform android` bundles cleanly (588
  modules) with `react-native-get-random-values` imported before
  `@pqc-sdk/core`. `docs/compatibility.md` is updated to reflect the SDK 54
  target. No runtime or public API change.

## 0.3.5

### Patch Changes

- 273cefe: Fold `prettier --check .` into the `lint` turbo task (as a `//#format:check`
  root task dependency), so a single `pnpm lint` — locally and in CI — surfaces
  formatting issues alongside eslint/tsc, instead of relying on a separate
  `format:check` step that's easy to skip when running the gate by hand. Removes
  the now-redundant standalone "Format check" step from `.github/workflows/ci.yml`.
  No runtime or public API change.
- 273cefe: Pin `examples/react-native-expo` back to Expo SDK 56 (from SDK 57). Expo Go's
  Play Store release does not support SDK 57 yet — its build is still in app
  store review — so the example targets the SDK that Expo Go can actually run
  today. `expo install expo@^56.0.0 --fix` realigned `react-native` (0.86.0 →
  0.85.3), `expo-status-bar`, and `typescript`; `expo-doctor` reports 21/21
  checks passing and `npx expo export --platform ios` still bundles cleanly
  with `react-native-get-random-values` imported before `@pqc-sdk/core`.
  `docs/compatibility.md` is updated to reflect the SDK 56 target and note that
  SDK 57 support is pending Expo Go's own store approval, not a PQC SDK
  limitation. No runtime or public API change.

## 0.3.4

### Patch Changes

- 914b654: Fold `prettier --check .` into the `lint` turbo task (as a `//#format:check`
  root task dependency), so a single `pnpm lint` — locally and in CI — surfaces
  formatting issues alongside eslint/tsc, instead of relying on a separate
  `format:check` step that's easy to skip when running the gate by hand. Removes
  the now-redundant standalone "Format check" step from `.github/workflows/ci.yml`.
  No runtime or public API change.

## 0.3.3

### Patch Changes

- 744d59e: Add `examples/react-native-expo`, a real Expo (TypeScript) app that validates
  `@pqc-sdk/core` with the genuine `react-native-get-random-values` entropy
  polyfill (native OS randomness), not the `Math.random` shim used for the
  Day-0 standalone Hermes engine test. The app type-checks and bundles cleanly
  through Metro (595 modules, Hermes bytecode output) with no simulator/emulator
  available in this environment to run it on-device; `docs/compatibility.md` is
  updated to "harness ready, on-device run pending" rather than a false ✅, with
  the concrete findings (Metro bundle succeeds; standalone Hermes execution of
  the real RN bundle fails on bytecode-version mismatch and on private
  class-field syntax in the `react-native` package itself).

  Also pins `typescript` as an explicit devDependency in `@pqc-sdk/core` and
  `@pqc-sdk/cli` (previously relied on hoisting from the workspace root).
  Adding the Expo example introduced a second `typescript` version into the
  workspace, which made `tsup`'s peer resolution for its DTS build
  nondeterministic and broke `@pqc-sdk/core`'s build; pinning the version
  locally removes the ambiguity regardless of what other workspace packages
  require. No runtime or public API change.

## 0.3.2

### Patch Changes

- 04bc7b4: Add fast-check fuzzing for the `deserialize` parser, the SDK's primary attack
  surface for untrusted input. The suite asserts a single fail-closed invariant
  over thousands of hostile tokens — arbitrary/unicode/control-char strings,
  wrong segment counts, unknown algorithms and uses, valid base64url of the wrong
  length, off-by-one lengths, invalid and non-canonical base64url, the impossible
  `% 4 === 1` length, truncated prefixes, and injected dots — across both the
  untyped and typed (`{ algorithm, use }`) overloads: `deserialize` either returns
  a structurally consistent key or throws a `PqcError`, never anything else.
  Hand-picked regressions name the nastiest cases, and the truncation case covers
  every prefix slice of a valid token. Test-only; no API or runtime change.

## 0.3.1

### Patch Changes

- 6fcd7a4: Stabilize the multi-megabyte encrypt/decrypt round-trip test against CI flakes.
  It ran on the default 5s timeout, which is too tight when `turbo run test`
  executes the core and CLI suites concurrently and v8 coverage instrumentation
  slows the 3 MB operation under CPU contention. Give it a generous explicit
  timeout so it cannot flake. Test-only; no API or runtime change.
- 6fcd7a4: Add property-based tests (fast-check) that assert the core crypto invariants
  over many generated inputs, complementing the example-based suite:
  `decrypt(encrypt(x))` round-trips for any payload; any single-byte tamper of a
  ciphertext fails closed with a `PqcError` and never returns plaintext;
  `deserialize(serialize(k))` preserves any key; a genuine signature verifies and
  any single-byte tamper of the signature or message is rejected; and base64url
  round-trips for any byte array. Runs are seeded for deterministic CI and bounded
  so test time stays modest. Dev-dependency and tests only; no API or runtime
  change.
- 6fcd7a4: Close the last open edge-case coverage gap from the June 2026 audit (finding
  I1): the `verify` defense-in-depth catch path is now exercised by a focused
  regression test. It proves `verify` fails closed to `false` if the underlying
  signer ever throws — no signature byte-pattern makes `@noble`'s verify throw in
  practice (it returns `false` for every malformed signature), so the signer is
  stubbed to throw to genuinely cover the branch. Test-only; no API or runtime
  behavior change.

## 0.3.0

### Minor Changes

- 499b31f: Harden the core API and crypto surface:

  - `deserialize(token, { algorithm, use })` is a new typed overload that returns a
    narrow key type (e.g. `PublicKey<'ml-kem-768'>`), so deserialized keys drop
    straight into `encrypt`/`sign` without an `as never` cast. A mismatch throws
    `WRONG_ALGORITHM` or `WRONG_KEY_USE`. The `ExpectedKey` type is now exported.
  - Signature `context` longer than the FIPS 204 limit of 255 bytes now throws a
    `PqcError('INVALID_CONTEXT')` consistently from both `sign` and `verify`
    (previously `sign` leaked a raw error and `verify` silently returned `false`).
  - `decapsulate` now runs inside `decrypt`'s try/catch, so any unexpected throw is
    normalized to the documented `DECRYPTION_FAILED` instead of leaking upstream.
  - The `@noble/post-quantum` and `@noble/ciphers` cryptographic dependencies are
    pinned to exact versions so a downstream install gets the build that passed the
    NIST vectors.

## 0.2.0

### Minor Changes

- 156cfee: Core correctness fixes for ML-KEM hybrid encryption and base64url decoding.

  - **Fix package description**: drop `SLH-DSA` from the package description, since
    only ML-KEM-768 and ML-DSA-65 are implemented (`SUPPORTED_ALGORITHMS`).
  - **Authenticate the ciphertext header**: the 2-byte header (`FORMAT_VERSION`,
    `headerId`) is now bound as AES-GCM additional authenticated data on both
    encrypt and decrypt, so it is covered by the GCM tag.

    > **Breaking change to the ciphertext format.** This changes the authenticated
    > wire format: ciphertexts produced by `0.1.2` are **not** decryptable by this
    > release, and ciphertexts produced by this release are not decryptable by
    > `0.1.2`. Re-encrypt any data that must remain readable across the upgrade.

  - **Reject non-canonical base64url**: `fromBase64Url` now throws a `TypeError`
    when the trailing bits of the final group are non-zero, instead of silently
    decoding non-canonical input.

## 0.1.2

### Patch Changes

- 82bbac3: Translate all user-facing text to English: CLI command and flag descriptions,
  CLI output (success messages, warnings, audit report, errors), files generated
  by `pqc init`, every typed error message in core, the full public API JSDoc
  (including examples, which feed the generated API reference), package
  descriptions, and both READMEs. Error `code` values are unchanged, so programs
  handling `PqcError` by code are unaffected.

## 0.1.1

### Patch Changes

- c2dbf93: Fix: el export `version` ahora se inyecta en build time desde el `package.json`
  del paquete, en vez de estar hardcodeado. Los bumps de changesets se reflejan
  solos en ESM, CJS y los types.

## 0.1.0

### Minor Changes

- aac9044: Primera release pública: API de cifrado híbrido ML-KEM-768 + AES-256-GCM,
  firmas ML-DSA-65 con context strings, serialización de keys a base64url, y CLI
  con `init`, `keygen` y `audit`.
