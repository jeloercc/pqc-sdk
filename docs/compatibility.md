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

## X-Wing (hybrid KEM, `pqcenc.v2`)

X-Wing (`pqc.keys.generate({ algorithm: 'x-wing' })`) is a separate code path
(`@noble/post-quantum/hybrid.js`) from ML-KEM-768, so it is tracked with its
own compatibility row per the same real-execution rule: a runtime only gets
✅ once the actual roundtrip ran on that runtime, not by inference from the
ML-KEM-768 result above.

| Runtime              | Result                                                 | Notes                                                                                                                                  |
| -------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Node                 | ✅ verified 2026-07-20                                 | Same example (`examples/node`), extended with an x-wing roundtrip.                                                                     |
| Deno                 | ✅ verified 2026-07-20                                 | Import map needed one addition: `@noble/post-quantum/hybrid.js`.                                                                       |
| Cloudflare Workers   | ✅ verified 2026-07-20 (local workerd, `wrangler dev`) | Same bundle, no extra config; ciphertext 32 bytes larger than v1.                                                                      |
| Hermes (RN's engine) | ⏳ not yet run                                         | Needs the standalone Hermes CLI re-run with an x-wing case, as was done for ML-KEM-768 on 2026-06-12. Not executed this sprint.        |
| React Native         | ⏳ not yet run                                         | Needs an on-device roundtrip through `examples/react-native-expo`, as was done for ML-KEM-768 on 2026-07-02. Not executed this sprint. |

Measured ciphertext sizes for the message `'roundtrip on <runtime>'` (23–31
bytes depending on runtime), confirming the pqcenc.v2 1150-byte overhead
(docs/serialization-format.md §2.2): Node 1173 B, Deno 1167 B, Workers 1181 B
— each exactly 1150 + the plaintext length actually sent.

## Streaming (chunked envelope, `docs/serialization-format.md` §9)

`pqc.encryptStream`/`decryptStream` (and the Web Streams adapters
`encryptWebStream`/`decryptWebStream`) are async-iterable-based specifically
so the core primitive needs nothing from the host runtime beyond the
language itself — but "needs nothing" is not the same as "verified," so
this gets its own row set per the same real-execution rule as X-Wing above.
The Web Streams adapters additionally depend on the host's `TransformStream`/
`ReadableStream`/`WritableStream` implementation, which is why runtimes are
tracked separately from the core-primitive claim.

| Runtime              | Result                                                 | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node                 | ✅ verified 2026-07-22                                 | `examples/node`: a real 8 MiB file, `fs.createReadStream`/`createWriteStream` bridged via `Readable.toWeb`/`Writable.toWeb`, piped through both adapters end to end, byte-for-byte match confirmed. Both KEMs.                                                                                                                                                                                                                                                                                                                         |
| Deno                 | ✅ verified 2026-07-22                                 | `examples/deno`: same 8 MiB roundtrip using `Deno.FsFile`'s native `.readable`/`.writable` (no bridging layer needed — already WHATWG streams). Both KEMs.                                                                                                                                                                                                                                                                                                                                                                             |
| Cloudflare Workers   | ✅ verified 2026-07-22 (local workerd, `wrangler dev`) | `examples/cloudflare-workers`: no filesystem in workerd, so a 4 MiB in-memory synthetic payload (smaller than Node/Deno's, to stay inside the CPU-time budget) piped through both adapters in a single request; response includes `byteForByteMatch: true` for both KEMs.                                                                                                                                                                                                                                                              |
| Hermes (RN's engine) | ⏳ not yet run                                         | Same gap as x-wing's row above and for the same reason (no standalone Hermes CLI binary in the implementing environment this sprint) — see issue [#45](https://github.com/jeloercc/pqc-sdk/issues/45), which already tracks closing this exact kind of gap for streaming's core primitive. The async-iterable core needs nothing Hermes-specific in principle (plain async generators are part of the language, not a host API), but that is exactly the kind of claim the honest-compatibility rule says stays ⏳ until actually run. |
| React Native         | ⏳ not yet run                                         | Same as above — needs an on-device roundtrip through `examples/react-native-expo`, tracked by issue #45. The Web Streams adapters have an additional open question RN raises that ml-kem-768/x-wing's one-shot API doesn't: whether Hermes/RN's `TransformStream`/`ReadableStream` support (if any) is complete enough for the adapters, or whether RN apps on this SDK should use the async-iterable core directly. Not answered here — requires an actual device test, not inference.                                                |

**x-wing streaming** required zero additional code (`packages/core/src/stream.ts`
was algorithm-generic from Day 1 of the streaming sprint), so it shares
these same rows rather than getting its own separate table, unlike x-wing's
one-shot rows above.

## Node (`examples/node`)

No limitations. Direct ESM, no flags. The CJS build also works
(`require('@pqc-sdk/core')`), verified in the previous step's smoke tests.
Extended 2026-07-20 with an x-wing roundtrip (same example, no new flags):
ml-kem-768 ciphertext 1141 B, x-wing ciphertext 1173 B for the same 23-byte
message — the 32-byte difference is exactly the v1→v2 overhead delta
(1150 − 1118).

## Deno (`examples/deno`)

Works, with two **temporary** caveats (they disappear once published to npm):

1. Since `@pqc-sdk/core` is not published, the import map in `deno.json` points
   to the local build and must also map the `@noble/*` bare specifiers that the
   ESM bundle leaves as externals (Deno resolves them via `npm:`). Once the
   package is published, `"@pqc-sdk/core": "npm:@pqc-sdk/core"` is enough.
2. `--allow-read` to read the local dist. Not needed with the package from npm.

No `node_modules` or `nodeModulesDir` was needed: Deno's `npm:` resolution
handles the transitive dependencies (@noble/hashes) on its own.

**x-wing (2026-07-20)**: the import map needed one more entry —
`"@noble/post-quantum/hybrid.js": "npm:@noble/post-quantum@^0.6.1/hybrid.js"`
— alongside the existing `ml-kem.js`/`ml-dsa.js` mappings; without it Deno
refuses the import with "not a dependency and not in import map". Once added,
the roundtrip ran with no other changes.

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
- **x-wing (2026-07-20)**: same worker extended to also run an x-wing
  roundtrip in the same request, verified against a real `wrangler dev`
  local workerd instance (not just `--dry-run`): `{"ok":true,
"algorithm":"ml-kem-768","ciphertextBytes":1149,...,"hybrid":{"ok":true,
"algorithm":"x-wing","ciphertextBytes":1181,...}}`. No bundle or
  `nodejs_compat` changes needed — `hybrid.js` uses the same standard APIs.

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

**x-wing**: not re-run on Hermes this sprint (2026-07-20) — the standalone
CLI binary was not available in the environment that implemented the
`pqcenc.v2` envelope. Stays ⏳ in the table above until an actual Hermes
execution (interpreted or precompiled bytecode) exercises an x-wing key
pair, per the honest-compatibility rule.

**streaming**: same gap, same reason, not re-run this sprint (2026-07-22) —
tracked by issue [#45](https://github.com/jeloercc/pqc-sdk/issues/45)
alongside x-wing's Hermes row. Stays ⏳ until an actual Hermes execution
exercises `encryptStream`/`decryptStream` (and ideally the Web Streams
adapters, to also confirm Hermes's `TransformStream` support one way or
the other).

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

**x-wing**: not re-run on a physical device this sprint (2026-07-20) — no
device was available in the environment that implemented the `pqcenc.v2`
envelope. Stays ⏳ in the table above until an on-device roundtrip with an
x-wing key pair is recorded here, the same way the ML-KEM-768 row was closed
on 2026-07-02.

**streaming**: same gap, same reason, not re-run this sprint (2026-07-22) —
tracked by issue [#45](https://github.com/jeloercc/pqc-sdk/issues/45)
alongside x-wing's device row. Stays ⏳ until an on-device roundtrip through
`encryptStream`/`decryptStream` (or the Web Streams adapters) is recorded
here.

## General limitations (inherited from @noble/post-quantum)

- No constant-time guarantees (JS with JIT); documented in the research notes.
- React Native: validated end to end — Hermes engine standalone (see above)
  and the full roundtrip on a physical Android device via Expo Go, SDK 54
  (see `examples/react-native-expo`). Hermes does not ship
  `crypto.getRandomValues`: import `react-native-get-random-values` before
  the SDK.
