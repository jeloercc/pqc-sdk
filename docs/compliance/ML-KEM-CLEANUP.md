# ML-KEM owned-buffer cleanup follow-up

Date: 2026-11-21. Baseline: core 0.12.0 at
`e55ca5d17aa82bee1390e2aa77674dd63150b6ef`; changes described here are unreleased.
The provider remains vendored `@noble/post-quantum` 0.7.1 with hashes 2.4.0.

The review found concrete omissions beyond JavaScript's runtime limitations:
sampling PRF outputs were not wiped after use, late decapsulation failures skipped
outer cleanup, and some polynomial/helper scratch survived normal or exceptional
exits. The fixes preserve arithmetic, designated outputs and caller-owned input.

| Ownership boundary                  | Implemented behavior                                                                                                                                                           | Regression evidence                                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| PRF output vs borrowed byte sampler | The owning wrapper wipes its digest after sampling, including failures; the byte sampler leaves borrowed input intact                                                          | `cleanup.test.ts`, sampling and eta=2/3 borrowed-input cases                                       |
| Outer decapsulation                 | Both ordinary/prepared paths clear assigned message, digest/coins, reencryption buffer and alternate candidate in `finally`                                                    | Retained-buffer observations with pre-assignment dependency and post-assignment selection faults   |
| Polynomial helpers                  | Reencryption wipes uncompressed u/v, disposable products and partial scratch; decryption tracks partially decoded vectors; keygen tracks its seed expansion and owned products | Source-attributed allocation/slice observation across all sets and first/middle/final fault stages |
| Failed encapsulation                | A candidate that was not returned is wiped; successful shared-secret output remains available                                                                                  | Helper faults on ordinary/prepared encapsulation plus independent normal-output controls           |
| Encoding helpers                    | Owned child encodings and partial aggregate outputs clear on failure; borrowed raw fields remain intact                                                                        | Partial key-encoding faults and existing ML-DSA checks for the shared helpers                      |

All cleanup tests run in child processes. Hooks are restored, observation counts
are checked and functional cases repeat without instrumentation. Expected results
come from the pinned official samples rather than a second copy of the algorithm.
Only public synthetic inputs are used; observations serialize metadata and
booleans, not intermediate values. Retained references change liveness and may
affect optimization, so the results are bounded to visible buffer behavior.

The persistent independent oracle checks 240 official public sample cases:
80 per set, including 25 direct Encaps ciphertext/shared-secret comparisons.
Exact source revision, raw-byte hashes and case inventories are in
`packages/core/src/vectors/acvp/ml-kem/manifest.json`. Existing locally generated
fixtures and golden serialization bytes remain unchanged. Additional tests guard
all-set length boundaries, coefficient/hash offsets, prepared-key binding and
the KEM entropy draw independently of the later AES-GCM nonce.

The baseline tests first reproduced missing cleanup. After the changes, the same
cleanup targets pass alongside the independent oracle. Disposable local mutation
checks deliberately alter produced ciphertext/secret values or remove checks and
wipes; the corresponding regressions fail. Mutation results and exact run evidence
belong to the implementation review, not a new public certification claim.

This follow-up does not change the F203-18 row's historical
**CONFORMING (with documented language limitation)** label or adopt an assessor's
decision. The baseline review recommended reopening that row because of fixable
omissions; repairs require reassessment rather than automatic closure. Primitive
flags, runtime-managed copies/registers and compiled constant-time behavior remain
outside the guarantees established by these tests. Host RBG and other existing
interpretation questions remain open. See the canonical matrix's §4.3.

The SDK default remains X-Wing. No public format, algorithm registry, provider
version or runtime floor changes. Third-party licenses and pristine hashes remain.
