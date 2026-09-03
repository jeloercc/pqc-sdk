---
'@pqc-sdk/cli': patch
'@pqc-sdk/core': patch
---

`pqc audit` now states its limits wherever it speaks. The help text, the runtime banner, and both READMEs describe it as a heuristic, non-exhaustive regex scan — a starting point for a migration review, not a substitute for one. A clean run says so explicitly ("not a clean bill of health: it means the patterns above did not match, not that none exists") rather than leaving "No pre-quantum crypto detected" to be read as a guarantee, and findings are framed as candidates to confirm rather than a finished migration list. The scan itself is unchanged; only its framing is.

Documentation: a new **How this is verified** section in the root README maps each layer the SDK actually owns — envelope format, key serialization, nonce derivation, fail-closed parsing — to the suite that covers it, linking the NIST ACVP vectors, golden serialization vectors, parser fuzzing, `fast-check` property tests, the streaming mutation matrix, the format spec, the audit and security reviews, and the runtime compatibility record. It also states plainly that those reviews are internal and AI-assisted rather than an independent third-party audit, and surfaces the absence of memory zeroization from `SECURITY.md` into the README where adopters will actually see it.
