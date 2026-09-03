---
'@pqc-sdk/core': patch
---

Documentation only: `docs/compatibility.md` now records the React Native rows as ✅ for the async-iterable core path, validated on a physical Android device via Expo Go (SDK 54) with genuine native entropy from `react-native-get-random-values`. ML-KEM-768, X-Wing, ML-DSA-65, streaming roundtrips for both KEMs, and the streaming tamper case (rejected with `PqcError` `DECRYPTION_FAILED`) all pass on device, with per-step timings recorded. The Hermes standalone engine rows are closed in the same pass for X-Wing and streaming.

The Web Streams adapters (`encryptWebStream`/`decryptWebStream`) stay ❌ on React Native — Hermes provides no `TransformStream`/`ReadableStream` and RN does not polyfill them. That is a permanent platform fact rather than a pending item, and the doc names the async-iterable core as the supported path on that runtime.

No code change: no published API, envelope layout or behaviour is affected.
