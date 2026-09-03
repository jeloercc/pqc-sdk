---
'@pqc-sdk/core': patch
---

Fixes a documentation defect that mattered: the hybrid-encryption and streaming guides still described `ml-kem-768` as the algorithm `pqc.keys.generate()` returns, contradicting the README and, in the hybrid guide, contradicting itself two sections later. X-Wing has been the default since 0.8.0. In a cryptography library a stale default in the docs is a real hazard — a reader following the guide would believe they had a pure-PQ key where the SDK produced a hybrid one, or the reverse. Every statement of the default now agrees, and the algorithm-comparison table was rebuilt with X-Wing first (its rows had been left in the old column order) plus a FIPS-scope row.

Makes existing streaming guarantees discoverable without reading source. The streaming guide gains a section on how each chunk is bound to its position and to the stream: the 11-byte big-endian chunk counter and final-chunk flag forming the nonce, the header bound as AAD on every chunk, fresh KEM encapsulation per stream, and the rule that a stream may only end after a chunk that authenticated as final. It also documents that the mutation matrix tests all of this adversarially against both KEMs, enumerating what it covers.

Adds a visible security-status note to the README: no independent third-party audit, no constant-time guarantees, no memory zeroization, linking `SECURITY.md` for the full threat model.

Reframes the "PQC in 30 minutes" claim to be about the API surface specifically, and says plainly that key management, format versioning, rotation and interoperability are the hard parts of a real migration and remain the adopter's problem.
