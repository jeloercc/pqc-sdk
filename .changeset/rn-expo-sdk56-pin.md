---
'@pqc-sdk/core': patch
---

Pin `examples/react-native-expo` back to Expo SDK 56 (from SDK 57). Expo Go's
Play Store release does not support SDK 57 yet — its build is still in app
store review — so the example targets the SDK that Expo Go can actually run
today. `expo install expo@^56.0.0 --fix` realigned `react-native` (0.86.0 →
0.85.3), `expo-status-bar`, and `typescript`; `expo-doctor` reports 21/21
checks passing and `npx expo export --platform ios` still bundles cleanly
with `react-native-get-random-values` imported before `@pqc-sdk/core`.
`docs/compatibility.md` is updated to reflect the SDK 56 target and note that
SDK 57 support is pending Expo Go's own store approval, not a PQC SDK
limitation. No runtime or public API change.
