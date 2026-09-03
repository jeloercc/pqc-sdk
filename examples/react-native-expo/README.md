# React Native (Expo)

Validates `@pqc-sdk/core` in a **real React Native app** — unlike
[`examples/hermes-standalone`](../hermes-standalone), which validates only the
Hermes engine with a `Math.random` shim standing in for entropy. This app uses
the genuine entropy polyfill,
[`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
(native OS randomness via `SecRandomCopyBytes` / `SecureRandom`), imported
**before** the SDK in [`App.tsx`](./App.tsx).

The single screen runs, on mount, everything the ⏳ rows in
[docs/compatibility.md](../../docs/compatibility.md) need from one device run
(issue [#45](https://github.com/jeloercc/pqc-sdk/issues/45)):

1. ML-KEM-768: generate → encrypt → decrypt → byte-compare the plaintext.
2. X-Wing: generate → encrypt → decrypt → byte-compare (the `pqcenc.v2`
   hybrid envelope).
3. ML-DSA-65: generate → sign → verify.
4. Streaming, both KEMs: `encryptStream`/`decryptStream` over a 4 KiB
   synthetic payload in 1 KiB chunks — four chunks, so the chunk counter,
   the final-chunk flag and chunk-to-chunk chaining are all exercised.
   Deliberately small: this proves chunking works on Hermes, it is not a
   throughput benchmark.
5. Streaming fail-closed: a bit is flipped in the last chunk's
   authentication tag and the decrypt must reject it with `PqcError`
   `DECRYPTION_FAILED`. A tampered stream that decrypted cleanly would be a
   failure, so this step passing is as load-bearing as the roundtrips.

Each step renders PASS/FAIL with its timing in milliseconds, and the screen
ends with a **Runtime** section reporting what the engine actually provides
(`Symbol.asyncIterator`, `TextDecoder`, `TransformStream`) — so a device run
records the engine's capabilities, not just pass/fail.

## Hermes and async iteration

Hermes implements **no part of ES2018 async iteration**. This is not a stale
toolchain artifact: React Native 0.81.5's own bundled compiler
(`sdks/hermesc`, `hermes-2025-07-07-RNv0.81.0`) rejects `async function*` and
`for await...of` outright. Metro's Babel preset downlevels both, which is why
the streaming API works on device at all.

Downlevelling leaves one gap, and [`asyncIteratorPolyfill.ts`](./asyncIteratorPolyfill.ts)
closes it. Babel's transpiled async generators expose their iterator method
under the **string** key `"@@asyncIterator"`, since `Symbol.asyncIterator`
does not exist to key it under. Babel's own `for await` helper looks there, so
Babel-compiled code is self-consistent — but `@pqc-sdk/core`'s `decryptStream`
performs an explicit `object[Symbol.asyncIterator]()` lookup, which evaluates
`object[undefined]` and throws `TypeError: undefined is not a function`.
Aliasing `Symbol.asyncIterator` to that same string resolves it. The alias
must be installed before `@pqc-sdk/core` is evaluated, hence its position as
the first import in `App.tsx`, alongside the entropy polyfill's identical
ordering requirement.

**The Web Streams adapters (`encryptWebStream`/`decryptWebStream`) are not
usable here**: Hermes provides no `TransformStream` or `ReadableStream`, and
React Native does not polyfill them. RN apps should use the async-iterable
core (`encryptStream`/`decryptStream`) directly, which is what this example
does. The screen reports `TransformStream` availability so a device run
confirms this rather than assuming it.

## Run on a simulator/emulator or device

```bash
pnpm build --filter=@pqc-sdk/core
cd examples/react-native-expo
pnpm ios      # or: pnpm android
```

## What was actually verified in this repo's environment, and what wasn't

This environment has no Xcode app and no Java/Android SDK, so **no simulator
or emulator could be launched here**. What was verified instead:

- **TypeScript**: `pnpm lint` (`tsc --noEmit`) passes against the real
  `react-native` and `@pqc-sdk/core` types.
- **Metro bundling**: `npx expo export --platform android` bundles the app —
  609 modules, including `@pqc-sdk/core`, `@noble/post-quantum`,
  `@noble/ciphers` and `react-native-get-random-values` — into Hermes
  bytecode (2.14 MB `.hbc`) with no resolution or transform errors. That the
  bytecode compiles at all is meaningful here: it means Metro's downlevelled
  async generators are accepted by RN's own `hermesc`.
- **Real Hermes execution of the SDK's streaming path**: the standalone
  Hermes CLI ran ML-KEM-768 and X-Wing one-shot roundtrips, both KEMs'
  streaming roundtrips at this example's exact 4 KiB / 1 KiB parameters, and
  the tamper case — all passing, using this directory's actual
  `asyncIteratorPolyfill.ts`. The SDK bundle was transformed with
  `@react-native/babel-preset` first, so the code under test is what Metro
  produces. Without the polyfill the streaming steps fail with
  `TypeError: undefined is not a function`, which is how the gap was found.

Note the standalone CLI cannot run the _app_ bundle (bytecode version skew,
and `react-native`'s own private-class-field syntax), which is why the SDK
path was exercised directly instead. Entropy there comes from the
`Math.random` shim, so it validates the engine, never the randomness.

**Conclusion: harness ready and the engine questions answered, on-device run
pending.** What remains is executing this app on a real device, which needs
Xcode or the Android SDK — neither is available in this environment.
[docs/compatibility.md](../../docs/compatibility.md) stays ⏳ until that run
happens, per the honest-compatibility rule.
