# FIPS 203/204/205 conformance self-assessment

This is the thing that distinguishes this SDK from wrapping
`@noble/post-quantum` directly: a clause-by-clause self-assessment against
all three PQC standards this SDK touches. Each matrix quotes the normative
text verbatim, states whether the requirement applies to this codebase, and
assigns one of a closed set of statuses — `CONFORMING`, `CONFORMING
(delegated)`, `NONCONFORMING`, `INDETERMINATE`, `NOT APPLICABLE` and so on —
never a bare pass/fail. A row moves to `CONFORMING` only on the strength of a
named, executed test; every row cites a file, a line, or a test name as its
evidence, never a narrative claim alone.

These pages are synced from the matrices in the repository's
[`docs/compliance/`](https://github.com/jeloercc/pqc-sdk/tree/main/docs/compliance)
directory, which stays the canonical copy — edit there, not here. The
[README](https://github.com/jeloercc/pqc-sdk#fips-203204205-conformance-self-assessment)
carries a shorter summary of the same findings.

| Matrix                           | Standard        | Requirements | Status                                                    |
| -------------------------------- | --------------- | ------------ | --------------------------------------------------------- |
| [FIPS 203 (ML-KEM)](./fips-203)  | ML-KEM-768      | 21           | 0 `NONCONFORMING`; 3 `INDETERMINATE`                      |
| [FIPS 204 (ML-DSA)](./fips-204)  | ML-DSA-44/65/87 | 22           | 0 `NONCONFORMING`; 3 `INDETERMINATE`                      |
| [FIPS 205 (SLH-DSA)](./fips-205) | SLH-DSA         | 21           | All `NOT APPLICABLE` — not implemented, by scope decision |

**What was found, and fixed.** Six findings were opened as `NONCONFORMING`
across the first two matrices and closed by an actual code change: two
floating-point-arithmetic findings (ML-KEM's `Compress_d`, ML-DSA's
`Decompose`/`Power2Round`/`HINT_M`), a branch-based implicit-reject
selection in ML-KEM decapsulation, missing zeroization on ML-DSA's
verification path, an RBG failure misattributed as an invalid key, and a
wrong-length public key throwing instead of returning `false`. Each has a
one-line summary and finding ID in the README section linked above, and the
full account — with the executed test that closed it — in the matrix
itself.

**What is not claimed.** This is self-assessment, not CMVP validation.
Nothing here has been submitted to, or evaluated under, NIST's
Cryptographic Module Validation Program or Cryptographic Algorithm
Validation Program. Most `INDETERMINATE` rows depend on the host
platform's random-bit generator — a property of whatever runs
`crypto.getRandomValues` on the deploying platform, not visible to this
assessment — and cannot be settled from inside a library. SLH-DSA (FIPS 205) is deliberately unimplemented, not an unexamined gap; see the FIPS 205
matrix for the scope decision and its reasoning.

None of the three matrices' row counts should be read as a score. Each
matrix's own §4.1 says so explicitly: an empty `NONCONFORMING` column is not
a compliance claim, and the rows are not of equal weight.
