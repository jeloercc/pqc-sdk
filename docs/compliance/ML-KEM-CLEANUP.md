# ML-KEM owned-buffer cleanup follow-up

Date: 2026-11-21. Baseline: core 0.12.0 at
`e55ca5d17aa82bee1390e2aa77674dd63150b6ef`. The follow-up is recorded in the
core 0.12.1 changelog; this baseline identifies the original assessment.
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

The 2026-11-27 repository reassessment records F203-18 as **INDETERMINATE** for
the stated scope. The earlier CONFORMING (with documented language limitation)
label and pre-fix recommendation remain historical. The repairs address the
identified secret-scratch omissions; the public intermediate, primitive/runtime
and module-boundary questions below remain explicit. No sample/overwrite result
is treated as official validation or universal physical-erasure evidence.

The SDK default remains X-Wing. No public format, algorithm registry, provider
version or runtime floor changes. Third-party licenses and pristine hashes remain.

## Public intermediate scope review (2026-11-27)

The secret-scratch observations above are bounded; they do not inventory every
non-output value. In the released source, ordinary decapsulation computes a public
key-check digest at
[`ml-kem.ts:734`](https://github.com/jeloercc/pqc-sdk/blob/c2f2ccfcce1f6f3fd1c5cba7bdfe20eec74aeb8a/packages/core/src/vendor/ml-kem/ml-kem.ts#L734).
Prepared mode retains H(ek) at
[`ml-kem.ts:779`](https://github.com/jeloercc/pqc-sdk/blob/c2f2ccfcce1f6f3fd1c5cba7bdfe20eec74aeb8a/packages/core/src/vendor/ml-kem/ml-kem.ts#L779);
its exposed clean method delegates to the arithmetic cache and does not overwrite
that separate hash buffer. Public modulus-validation scratch is also excluded
from the existing secret-scratch observer success totals.

A synthetic, assessment-only check retained SHA3-256 digest outputs (Keccak suffix
0x06, output length 32) while running each set's ordinary decapsulation with a
valid ciphertext, implicit rejection and a bad stored hash, then checked prepared
mode after clean. Key generation and encapsulation occurred before observation.
The first ordinary digest is the public H(ek) check, not a shared-secret output.
On each of Node 20.20.2, 24.22.3 and 26.13.0, all 12 retained public hash buffers
were nonzero after the relevant exit. Ordinary outcomes matched uninstrumented
controls and inputs were unchanged. Hooks were restored in finally; records
contained only counts, source sites and booleans, never secret values.

Retaining references changes liveness, so these results do not prove what an
uninstrumented collector retains. They are public derived data, not evidence of
secret-key recovery. They identify an applicability question for the full
intermediate-destruction wording and its stated exceptions. Primitive boolean,
register/copy/JIT behavior and the broader SDK/module lifecycle also remain
outside the guarantee established by the buffer probes. The scope must be stated
explicitly rather than treating all remaining questions as a language limitation.
