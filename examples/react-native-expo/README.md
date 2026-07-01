# React Native (Expo)

Validates `@pqc-sdk/core` in a **real React Native app** — unlike
[`examples/hermes-standalone`](../hermes-standalone), which validates only the
Hermes engine with a `Math.random` shim standing in for entropy. This app uses
the genuine entropy polyfill,
[`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
(native OS randomness via `SecRandomCopyBytes` / `SecureRandom`), imported
**before** the SDK in [`App.tsx`](./App.tsx).

The single screen runs, on mount:

1. ML-KEM-768: generate → encrypt → decrypt → byte-compare the plaintext.
2. ML-DSA-65: generate → sign → verify.

Each step renders PASS/FAIL with its timing in milliseconds.

## Run on a simulator/emulator or device

```bash
pnpm build --filter=@pqc-sdk/core
cd examples/react-native-expo
pnpm ios      # or: pnpm android
```

## What was actually verified in this repo's environment, and what wasn't

This environment has no Xcode app (`xcrun simctl` unavailable, command line
tools only) and no Java/Android SDK, so **no simulator or emulator could be
launched here**. What was verified instead:

- **TypeScript**: `pnpm lint` (`tsc --noEmit`) passes against the real
  `react-native` and `@pqc-sdk/core` types.
- **Metro bundling**: `npx expo export --platform ios` bundles the app —
  595 modules, including `@pqc-sdk/core`, `@noble/post-quantum`,
  `@noble/ciphers`, and `react-native-get-random-values` — into Hermes
  bytecode with no resolution or transform errors. This is a stronger signal
  than the standalone example: it goes through the actual Metro/Babel
  pipeline RN ships, not esbuild.
- **Standalone Hermes execution of the real bundle was attempted and failed**,
  for reasons that confirm a real device/simulator can't be substituted:
  - The precompiled bytecode Metro emits for RN 0.86 is bytecode version 98;
    the latest published standalone Hermes CLI (v0.13.0) only reads up to
    version 96 (`Error deserializing bytecode: Wrong bytecode version`).
  - Re-exporting as plain JS (`--no-bytecode`) and interpreting it instead
    fails to even parse: the `react-native` package itself (not our app code)
    uses private class fields (`#x`), a syntax the standalone CLI's older
    parser rejects. The Day-0 Hermes-engine test never hit this because it
    only bundled the SDK, not the `react-native` package.
  - This is also why `react-native-get-random-values` can't be exercised
    standalone: its `index.js` does `require('react-native')` at module scope
    just to read `NativeModules`, so loading it at all pulls in the same
    `react-native` package that fails to parse above.

**Conclusion: harness ready, on-device/simulator run pending.** The harness
(this app) is built, type-checks, and bundles cleanly through the real Metro
pipeline with the genuine polyfill wired in the correct order. What remains is
executing it on an actual iOS/Android simulator or device, which needs Xcode
or the Android SDK — neither is available in this environment. See
[docs/compatibility.md](../../docs/compatibility.md) for the documented
status (kept as "engine ✅ / app ⏳", not flipped to ✅).
