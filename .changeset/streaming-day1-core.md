---
'@pqc-sdk/core': none
---

Day 1 of the streaming-encryption sprint (`docs/proposals/streaming-encryption.md`): internal `encryptStream`/`decryptStream` core primitive (ml-kem-768 only) and the normative streaming envelope spec (`docs/serialization-format.md` §9). `none` because nothing in the published package's import surface changes — `dist/stream.js` is built but not listed in `package.json` `exports`, so it isn't reachable from `@pqc-sdk/core`. The real `minor` changeset lands when Day 3 exports this publicly.
