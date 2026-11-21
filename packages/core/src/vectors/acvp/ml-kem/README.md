# Pinned official ML-KEM public samples

These are byte-identical `internalProjection.json` public sample files from
[NIST ACVP-Server commit 975de31](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files).
`manifest.json` records the repository, exact commit, source paths, SHA-256 and
Git blob hashes, and every group/case identifier. No expected answer was generated
by this SDK. Tests run offline and validate the complete inventory before use.

Per parameter set there are 25 key-generation, 25 encapsulation, 10 decapsulation,
10 encapsulation-key-check and 10 decapsulation-key-check cases: 240 in total.
Direct Encaps tests compare produced ciphertext and shared secret with the
reference. Passing public samples is not official algorithm/module validation.

The existing `mlkem512-*` and `mlkem1024-*` files outside this directory declare
locally generated expectations and remain useful regression fixtures. Five legacy
768 key-generation cases match this source; legacy 768 encap/decap provenance was
not resolved against this pinned snapshot. Those facts do not imply an output
mismatch or rule out an older source. Existing golden bytes remain unchanged.

Retain upstream provenance. Do not reformat or regenerate these two raw snapshots;
their hashes refer to the exact upstream bytes. Updated samples require a new
explicit source revision and review, not refreshed answers from the code under test.
