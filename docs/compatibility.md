# Runtime compatibility

Results from the `examples/` projects (generate → encrypt → decrypt roundtrip
with ML-KEM-768 + AES-256-GCM), verified on 2026-06-11 (Hermes: 2026-06-12,
React Native on-device: 2026-07-02).

| Runtime              | Tested version             | Result                                                    | Required flags/config                                                        |
| -------------------- | -------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Node                 | 24.11 (target ≥20)         | ✅                                                        | None                                                                         |
| Deno                 | 2.8.2                      | ✅                                                        | Import map until published; `--allow-read`                                   |
| Cloudflare Workers   | wrangler 4 / local workerd | ✅                                                        | None — does not require `nodejs_compat`                                      |
| Hermes (RN's engine) | standalone CLI 0.12        | ✅ engine validated                                       | `crypto.getRandomValues` polyfill; transpile `class` (Metro does this in RN) |
| React Native         | Expo SDK 54 / RN 0.81      | ✅ Validated on physical Android device (Expo Go, SDK 54) | `react-native-get-random-values` imported before the SDK; see notes below    |

## Node (`examples/node`)

No limitations. Direct ESM, no flags. The CJS build also works
(`require('@pqc-sdk/core')`), verified in the previous step's smoke tests.

## Deno (`examples/deno`)

Works, with two **temporary** caveats (they disappear once published to npm):

1. Since `@pqc-sdk/core` is not published, the import map in `deno.json` points
   to the local build and must also map the `@noble/*` bare specifiers that the
   ESM bundle leaves as externals (Deno resolves them via `npm:`). Once the
   package is published, `"@pqc-sdk/core": "npm:@pqc-sdk/core"` is enough.
2. `--allow-read` to read the local dist. Not needed with the package from npm.

No `node_modules` or `nodeModulesDir` was needed: Deno's `npm:` resolution
handles the transitive dependencies (@noble/hashes) on its own.

## Cloudflare Workers (`examples/cloudflare-workers`)

- **Does not require `nodejs_compat`**: the SDK only uses standard APIs
  (`crypto.getRandomValues`, `TextEncoder`/`TextDecoder`, `Uint8Array`).
  Verified with `compatibility_date = 2025-01-01` on local workerd.
- **Bundle**: 78 KiB / 20 KiB gzip total upload (SDK + @noble/\*), measured
  with `wrangler deploy --dry-run`. Far below the free plan's 1 MiB limit.
- **CPU**: the full request (keygen + encapsulate + AES + decapsulate) took
  ~51 ms wall-clock in local dev. The Workers free plan limits CPU to 10 ms
  per request: doing **keygen + encrypt + decrypt in a single request** can
  exceed it. In real usage (one operation per request, persisted keys) each
  individual operation stays within budget, but measure with
  `wrangler dev --remote` before going to production on the free plan. On paid
  plans (30 s limit) there is no issue.

## Standalone Hermes (`examples/hermes-standalone`)

Validated on 2026-06-12 with the standalone Hermes CLI (binaries from the
[v0.13.0](https://github.com/facebook/hermes/releases/tag/v0.13.0) release,
Aug 2024, the binary reports 0.12.0 — the latest published standalone; the
Hermes embedded in current React Native is newer). Full roundtrip OK, both
interpreting the JS and executing bytecode precompiled with `hermesc` (the
format RN ships).

**What Hermes 0.12 provides of what the SDK needs:**

- ✅ `TextEncoder`, `BigInt`, `async/await`, generators, `??`/`?.`
- ❌ `crypto.getRandomValues` — in RN it is provided by
  `react-native-get-random-values` (import it **before** the SDK); in the
  standalone example it is shimmed only to validate the engine (the real
  polyfill uses NativeModules and cannot run without RN).
- ❌ `class` syntax — not a problem in RN (Metro/Babel always transpiles it);
  standalone it was transpiled with `@babel/plugin-transform-classes`.
- ❌ `TextDecoder` — the SDK does not use it internally (`decrypt` returns a
  `Uint8Array`), but if your app decodes to a string it needs a polyfill
  (e.g. `text-encoding-polyfill` or `fast-text-encoding`).

**Measured timings** (bytecode, x86_64, interpreted — Hermes has no JIT):
keygen 34 ms, encrypt 35 ms, decrypt 43 ms, ML-DSA-65 sign+verify 449 ms.
Slower than V8 but usable; keep ML-DSA signing off the UI thread.

**What was missing to mark React Native as ✅** — running the roundtrip in a
real RN app with `react-native-get-random-values` as the entropy source — was
closed by the on-device validation recorded below (July 2026).

## React Native app (`examples/react-native-expo`)

A minimal Expo (TypeScript) app that imports `react-native-get-random-values`
**before** `@pqc-sdk/core` and runs ML-KEM-768 generate → encrypt → decrypt and
ML-DSA-65 sign → verify on a single screen, rendering PASS/FAIL with timings.
This is the genuine entropy polyfill (native OS randomness via
`SecRandomCopyBytes` / `SecureRandom`), not the `Math.random` shim used to
validate the Hermes engine standalone.

**Target: Expo SDK 54** (matches the Expo Go version actually installed on
the test device, v54.0.8, which only supports SDK 54). Play Store rollout of
newer Expo Go builds lags per-device, so the example tracks what is
installable on the test hardware, not the latest SDK. Newer SDK support —
not a PQC SDK limitation — will be revisited once a newer Expo Go build
reaches the device.

**On-device validation (July 2026).** The roundtrip ran on a physical Android
device via Expo Go (SDK 54), with genuine native entropy from
`react-native-get-random-values` confirmed at runtime on screen. Results:
ML-KEM-768 generate 48 ms, encrypt 27 ms (1170-byte ciphertext), decrypt
28 ms, plaintext match PASS; ML-DSA-65 generate+sign 250 ms (3309-byte
signature), verify 77 ms. `TextDecoder` is available in this runtime.

See [examples/react-native-expo/README.md](../examples/react-native-expo/README.md)
for how to run it on an actual simulator or device.

## General limitations (inherited from @noble/post-quantum)

- No constant-time guarantees (JS with JIT); documented in the research notes.
- React Native: validated end to end — Hermes engine standalone (see above)
  and the full roundtrip on a physical Android device via Expo Go, SDK 54
  (see `examples/react-native-expo`). Hermes does not ship
  `crypto.getRandomValues`: import `react-native-get-random-values` before
  the SDK.
