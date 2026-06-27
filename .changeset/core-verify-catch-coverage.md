---
'@pqc-sdk/core': patch
---

Close the last open edge-case coverage gap from the June 2026 audit (finding
I1): the `verify` defense-in-depth catch path is now exercised by a focused
regression test. It proves `verify` fails closed to `false` if the underlying
signer ever throws — no signature byte-pattern makes `@noble`'s verify throw in
practice (it returns `false` for every malformed signature), so the signer is
stubbed to throw to genuinely cover the branch. Test-only; no API or runtime
behavior change.
