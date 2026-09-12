---
'@pqc-sdk/core': patch
---

Added a "FIPS 203/204/205 conformance self-assessment" section to README.md, linking the three clause-by-clause matrices under `docs/compliance/` (FIPS-203, FIPS-204, FIPS-205), summarizing the six findings closed by code changes (F203-11, F203-18, F203-19, F204-08, F204-10, F204-13), and stating plainly what is not claimed: this is self-assessment rather than CMVP validation, most `INDETERMINATE` rows depend on the host platform's RBG, and SLH-DSA remains deliberately unimplemented.

Docs only — no code, no published package output changed.
