---
'@pqc-sdk/core': patch
---

Record SLH-DSA (FIPS 205) as a deliberate scope decision, not an oversight

Documentation only — no API or behavior change. `README.md` and `SECURITY.md` gain a
short section stating that SLH-DSA is not implemented by choice: its signatures run
7,856–49,856 bytes (FIPS 205 Table 2, SLH-DSA-128s through 256f) versus 3,309 bytes for
ML-DSA-65; SPHINCS+'s hash-based construction costs tens of thousands of hash-function
invocations per signing/verification operation with no native acceleration available in
pure JS; and SLH-DSA's target use cases — firmware signing, long-lived roots of trust,
hedging against a lattice cryptanalytic break — aren't this SDK's request/response and
file-level target. ML-DSA-65 is recorded as the recommended signature algorithm, and a
consumer with a genuine SLH-DSA requirement is pointed toward a CMVP-validated module
rather than a self-assessed JS library.

`docs/compliance/FIPS-205-MATRIX.md` §1.3 records the same reasoning with a date
(2026-09-09) and explicit reopening conditions (§4.2, unchanged). All 21 rows stay
`NOT APPLICABLE` — what changes is that the reason is now a recorded decision rather than
a bare "not implemented," and the existing registry (all 12 Table 2 parameter sets mapped
against every applicable FIPS 205 requirement) is what makes that decision credible rather
than arbitrary.
