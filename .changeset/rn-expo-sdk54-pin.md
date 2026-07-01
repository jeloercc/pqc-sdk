---
'@pqc-sdk/core': patch
---

Roll `examples/react-native-expo` back to Expo SDK 54 (from SDK 56). The Expo
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
