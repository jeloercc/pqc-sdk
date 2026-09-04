# Runtime compatibility

Results from the `examples/` projects (generate → encrypt → decrypt roundtrip
with ML-KEM-768 + AES-256-GCM), verified on 2026-06-11 (Hermes: 2026-06-12,
React Native on-device: 2026-07-02, extended to X-Wing, streaming and the
Hermes engine on 2026-09-03).

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

| Runtime              | Result                                                    | Notes                                                                                                                                                                                                                                                  |
| -------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Node                 | ✅ verified 2026-07-20                                    | Same example (`examples/node`), extended with an x-wing roundtrip.                                                                                                                                                                                     |
| Deno                 | ✅ verified 2026-07-20                                    | Import map needed one addition: `@noble/post-quantum/hybrid.js`.                                                                                                                                                                                       |
| Cloudflare Workers   | ✅ verified 2026-07-20 (local workerd, `wrangler dev`)    | Same bundle, no extra config; ciphertext 32 bytes larger than v1.                                                                                                                                                                                      |
| Hermes (RN's engine) | ✅ engine validated 2026-09-03                            | Standalone Hermes CLI (v0.13.0 release, binary reports 0.12.0), same harness as the ML-KEM-768 run on 2026-06-12: x-wing generate → encrypt → decrypt roundtrip PASS. Engine validation only — entropy is the `Math.random` shim, never cryptographic. |
| React Native         | ✅ verified 2026-09-03 (physical Android, Expo Go SDK 54) | `examples/react-native-expo` on device with genuine native entropy: generate 32 ms (public 1216 B, secret 32 B seed), encrypt+decrypt 124 ms (envelope 1202 B), plaintext byte-match PASS.                                                             |

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

| Runtime              | Result                                                                              | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node                 | ✅ verified 2026-07-22                                                              | `examples/node`: a real 8 MiB file, `fs.createReadStream`/`createWriteStream` bridged via `Readable.toWeb`/`Writable.toWeb`, piped through both adapters end to end, byte-for-byte match confirmed. Both KEMs.                                                                                                                                                                                                                                                                                                                                                                                                  |
| Deno                 | ✅ verified 2026-07-22                                                              | `examples/deno`: same 8 MiB roundtrip using `Deno.FsFile`'s native `.readable`/`.writable` (no bridging layer needed — already WHATWG streams). Both KEMs.                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Cloudflare Workers   | ✅ verified 2026-07-22 (local workerd, `wrangler dev`)                              | `examples/cloudflare-workers`: no filesystem in workerd, so a 4 MiB in-memory synthetic payload (smaller than Node/Deno's, to stay inside the CPU-time budget) piped through both adapters in a single request; response includes `byteForByteMatch: true` for both KEMs.                                                                                                                                                                                                                                                                                                                                       |
| Hermes (RN's engine) | ✅ engine validated 2026-09-03 (core primitive) · ❌ Web Streams adapters           | Standalone Hermes CLI, with the SDK transformed through `@react-native/babel-preset` first so the code under test is what Metro produces: both KEMs' streaming roundtrips PASS at 4096 B in 1 KiB chunks, and a tampered chunk rejected with `DECRYPTION_FAILED`. This is also where the async-iteration gap was found — see the note below; without `Symbol.asyncIterator` aliased, `decryptStream` throws `TypeError: undefined is not a function`. `TransformStream`/`ReadableStream` are absent on this engine, so the adapters are ❌, not ⏳. Engine validation only — entropy is the `Math.random` shim. |
| React Native         | ✅ verified 2026-09-03 (core primitive, physical Android) · ❌ Web Streams adapters | `examples/react-native-expo` on device: 4096 B in 4 chunks → 5251 B (ml-kem-768, 63 ms) and → 5283 B (x-wing, 137 ms), plaintext byte-match PASS for both, and a tampered final chunk rejected with `PqcError` `DECRYPTION_FAILED` (60 ms). The ✅ covers `encryptStream`/`decryptStream` only. The **Web Streams adapters remain unavailable and this run does not change that**: Hermes provides no `TransformStream`/`ReadableStream` and React Native does not polyfill them. RN apps use the async-iterable core directly. See the known-limitation note below.                                            |

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
`"@noble/post-quantum/hybrid.js": "npm:@noble/post-quantum@^0.7.1/hybrid.js"`
— alongside the existing `ml-kem.js`/`ml-dsa.js` mappings; without it Deno
refuses the import with "not a dependency and not in import map". Once added,
the roundtrip ran with no other changes.

## Cloudflare Workers (`examples/cloudflare-workers`)

- **Does not require `nodejs_compat`**: the SDK only uses standard APIs
  (`crypto.getRandomValues`, `TextEncoder`/`TextDecoder`, `Uint8Array`).
  Verified with `compatibility_date = 2025-01-01` on local workerd.
- **Bundle**: 161 KiB / 43 KiB gzip total upload (SDK + @noble/\*), measured
  with `wrangler deploy --dry-run` on 2026-09-03. Still far below the free
  plan's 1 MiB limit. This replaces an earlier 78 KiB / 20 KiB figure measured
  on 2026-07-20: the bundle roughly doubled when x-wing (X25519) and the
  streaming envelope landed, and the example itself now exercises both KEMs
  plus a streaming roundtrip. Re-measure rather than quote this number if
  bundle size is a constraint for you.
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

**x-wing and streaming (2026-09-03).** Both were run on the standalone
Hermes CLI, closing the gap left open in July when no CLI binary was
available. The SDK was transformed with `@react-native/babel-preset` before
execution, so the code under test is what Metro actually produces rather
than an esbuild approximation. Results: x-wing generate → encrypt → decrypt
PASS; `encryptStream`/`decryptStream` PASS for both KEMs at 4096 B in 1 KiB
chunks; a tampered final chunk rejected with `PqcError` `DECRYPTION_FAILED`.
Entropy remains the `Math.random` shim, so this validates the engine and
never the randomness — the real-entropy claim rests on the device run below.

This run is also what surfaced the async-iteration gap described under
"Hermes and async iteration" in
[examples/react-native-expo/README.md](../examples/react-native-expo/README.md):
Hermes implements no part of ES2018 async iteration, and without
`Symbol.asyncIterator` aliased to Babel's `"@@asyncIterator"` key,
`decryptStream` throws `TypeError: undefined is not a function`. It also
settled the `TransformStream` question — the answer is that Hermes has none,
which is why the adapters are ❌ rather than ⏳.

## React Native app (`examples/react-native-expo`)

A minimal Expo (TypeScript) app that imports `react-native-get-random-values`
**before** `@pqc-sdk/core` and runs nine steps on a single screen, rendering
PASS/FAIL with timings: ML-KEM-768 and X-Wing generate → encrypt → decrypt,
ML-DSA-65 sign → verify, streaming roundtrips for both KEMs, and a streaming
tamper case that must fail closed. This is the genuine entropy polyfill
(native OS randomness via `SecRandomCopyBytes` / `SecureRandom`), not the
`Math.random` shim used to validate the Hermes engine standalone.

**Target: Expo SDK 54** (matches the Expo Go version actually installed on
the test device, v54.0.8, which only supports SDK 54). Play Store rollout of
newer Expo Go builds lags per-device, so the example tracks what is
installable on the test hardware, not the latest SDK. Newer SDK support —
not a PQC SDK limitation — will be revisited once a newer Expo Go build
reaches the device.

**Earlier on-device validation (July 2026), superseded by the run below but
kept as the record of when the ML-KEM-768 row was first closed.** The
roundtrip ran on a physical Android
device via Expo Go (SDK 54), with genuine native entropy from
`react-native-get-random-values` confirmed at runtime on screen. Results:
ML-KEM-768 generate 48 ms, encrypt 27 ms (1170-byte ciphertext), decrypt
28 ms, plaintext match PASS; ML-DSA-65 generate+sign 250 ms (3309-byte
signature), verify 77 ms. `TextDecoder` is available in this runtime.

See [examples/react-native-expo/README.md](../examples/react-native-expo/README.md)
for how to run it on an actual simulator or device.

**On-device validation, full surface (2026-09-03).** All nine steps of
`examples/react-native-expo` PASS on a **physical Android device via Expo Go
(SDK 54)**, with genuine native entropy from `react-native-get-random-values`
confirmed on screen — not a simulator, not the `Math.random` shim. This
closes the x-wing and streaming device rows together with the re-run of the
ML-KEM-768 and ML-DSA-65 paths, and closes issue
[#45](https://github.com/jeloercc/pqc-sdk/issues/45).

| Step                           | Result | Time   | Detail                                       |
| ------------------------------ | ------ | ------ | -------------------------------------------- |
| ML-KEM-768 generate            | PASS   | 52 ms  | public 1184 B, secret 2400 B                 |
| ML-KEM-768 encrypt + decrypt   | PASS   | 54 ms  | envelope 1170 B, plaintext matches           |
| X-Wing generate                | PASS   | 32 ms  | public 1216 B, secret 32 B seed              |
| X-Wing encrypt + decrypt       | PASS   | 124 ms | envelope 1202 B, plaintext matches           |
| ML-DSA-65 generate + sign      | PASS   | 468 ms | signature 3309 B                             |
| ML-DSA-65 verify               | PASS   | 78 ms  |                                              |
| Streaming ML-KEM-768 roundtrip | PASS   | 63 ms  | 4096 B in 4 chunks → 5251 B, bytes match     |
| Streaming X-Wing roundtrip     | PASS   | 137 ms | 4096 B in 4 chunks → 5283 B, bytes match     |
| Streaming tampered chunk       | PASS   | 60 ms  | rejected with `PqcError` `DECRYPTION_FAILED` |

The tamper step passing is the load-bearing one for the streaming envelope:
a flipped bit in the final chunk's authentication tag must fail closed on
the device exactly as it does under CI, and it did.

The streaming steps ran with `asyncIteratorPolyfill.ts` installed, as the
example always installs it. Which branch it took on this device — Hermes
supplying `Symbol.asyncIterator` natively (the alias no-ops) or the alias
being used — is not recorded here, because the on-screen Runtime line was
not captured in this run's report. Given RN 0.81.5's own `hermesc` rejects
async generators, the alias is the expected path, but that is an inference
and is deliberately not written down as a result.

**Known limitation — the Web Streams adapters do not work on React Native,
and this is permanent, not pending.** Hermes provides no `TransformStream`,
`ReadableStream` or `WritableStream`, and React Native ships no polyfill for
them, so `pqc.encryptWebStream`/`pqc.decryptWebStream` cannot run on this
runtime at all. **Use the async-iterable core — `pqc.encryptStream` /
`pqc.decryptStream` — directly on React Native**; it is the primary API and
needs nothing from the host beyond the language, which is exactly why the SDK
was built that way (`docs/proposals/streaming-encryption.md` §3). This is a
statement about the platform, not a to-do: no device run will change it, and
it is deliberately recorded separately from the core-primitive ✅ above,
which the 2026-09-03 device run closed.

Two further Hermes facts the same investigation established, since anything
depending on them needs to know: Hermes implements **no part of ES2018 async
iteration** — React Native 0.81.5's own bundled compiler (`sdks/hermesc`,
`hermes-2025-07-07-RNv0.81.0`) rejects `async function*` and `for await...of`
outright, so Metro's Babel preset downlevels them, which is what makes
`encryptStream`/`decryptStream` usable on device in the first place. And
because `Symbol.asyncIterator` does not exist there, Babel keys its
transpiled generators on the string `"@@asyncIterator"` instead, which breaks
the SDK's explicit `object[Symbol.asyncIterator]()` lookups until aliased —
see
[`examples/react-native-expo/asyncIteratorPolyfill.ts`](../examples/react-native-expo/asyncIteratorPolyfill.ts),
which the example installs before `@pqc-sdk/core`. Verified by executing the
SDK on the Hermes VM, not inferred.

## General limitations (inherited from @noble/post-quantum)

- No constant-time guarantees (JS with JIT); documented in the research notes.
- React Native: validated end to end — Hermes engine standalone (see above)
  and the full roundtrip on a physical Android device via Expo Go, SDK 54
  (see `examples/react-native-expo`). Hermes does not ship
  `crypto.getRandomValues`: import `react-native-get-random-values` before
  the SDK.
