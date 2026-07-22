---
'@pqc-sdk/core': none
---

Day 2 of the streaming-encryption sprint (`docs/proposals/streaming-encryption.md`): x-wing joins the streaming envelope (`encryptStream`/`decryptStream`, no code change needed — the Day 1 implementation was already algorithm-generic), plus the full mutation-check suite against both KEMs. `none` because nothing in the published package's import surface changes yet — the real `minor` changeset lands when Day 3 exports this publicly.
