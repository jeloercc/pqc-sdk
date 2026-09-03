---
'@pqc-sdk/core': patch
'@pqc-sdk/cli': patch
---

Accuracy pass over the project's public claims, plus better placement for the evidence behind them.

**Corrected overclaims.** `Bun` and `Browsers` were marked ✅ in the core README's compatibility table with no roundtrip ever executed on either — the same class of inaccuracy as audit finding M2. Both are now ⏳ with the reason stated. The Cloudflare Workers bundle figure said 78 KiB / 20 KiB gzip, measured in July before X-Wing and streaming landed; re-measured with `wrangler deploy --dry-run` it is 161 KiB / 43 KiB gzip, and the docs now say so, note what changed, and tell size-sensitive readers to measure rather than quote. The React Native row now states that streaming needs a `Symbol.asyncIterator` alias and that the Web Streams adapters do not work on Hermes. The npm package descriptions omitted X-Wing, which has been the default KEM since 0.8.0.

**Evidence moved up front.** The README's "How this is verified" section now precedes the quickstart and opens with the strongest signals: NIST ACVP vectors running in CI, five runtimes validated by actual execution (including a physical Android device), parser fuzzing, property tests, golden wire-format vectors and the streaming mutation matrix.

**Process stated plainly.** `CONTRIBUTING.md` gains a "Development process" section: development is AI-assisted, every commit carries a `Co-Authored-By` trailer, and the working agreements are checked in rather than hidden. It links `.claude/rules/crypto-review.md` as the standing discipline and is explicit that none of it substitutes for an independent third-party audit, which this project has not had.

No code or behaviour changes.
