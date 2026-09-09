# Third-party notice — vendored ML-KEM

This directory contains source code copied from a third-party package. It is **not**
original work of the `pqc-sdk` authors, and the license and copyright notice below apply
to it in full.

## Provenance

| Field               | Value                                           |
| ------------------- | ----------------------------------------------- |
| Source package      | `@noble/post-quantum`                           |
| Version vendored    | **0.7.1** (exact)                               |
| Upstream repository | https://github.com/paulmillr/noble-post-quantum |
| Upstream author     | Paul Miller (https://paulmillr.com)             |
| License             | MIT                                             |
| Date vendored       | 2026-09-07                                      |

### Files copied

Copied verbatim from the package's `src/` directory, then modified as recorded in each
file's header comment:

| File           | Upstream path      | sha256 of the pristine copy, before local edits                    |
| -------------- | ------------------ | ------------------------------------------------------------------ |
| `ml-kem.ts`    | `src/ml-kem.ts`    | `774c5e295b0fc82ceb3999f1f8a37a845fb0a48326a4648c5224b9ea49f0823b` |
| `_crystals.ts` | `src/_crystals.ts` | `6fd3e3340618c4da1d1bcde76893beed5ea642274f874e8b25dfea4af13660ec` |
| `utils.ts`     | `src/utils.ts`     | `4d257a3f99c8ac0d6e74116086021e125de7d012a827e68af1f0a91b57034a02` |

Those digests let a reviewer reproduce the starting point exactly:

```sh
shasum -a 256 node_modules/@noble/post-quantum/src/{ml-kem,_crystals,utils}.ts
```

`falcon.ts`, `ml-dsa.ts`, `slh-dsa.ts`, `hybrid.ts`, `webcrypto.ts` and `index.ts` are
**not** vendored. `@noble/hashes` and `@noble/curves` are **not** vendored either; they
remain ordinary external dependencies.

## Why this code is vendored

The published `dist` of `@pqc-sdk/core` imports `@noble/post-quantum` as an _external
runtime import_ rather than inlining it. Consumers therefore execute their own
registry-resolved copy of the package, and no local patch, `overrides` entry, or
`pnpm patchedDependencies` entry in this repository can reach them.

Two FIPS 203 findings recorded in `docs/compliance/FIPS-203-MATRIX.md` are located in the
provider's ML-KEM code:

- **F203-19** — `Compress_d` used IEEE-754 floating-point division, which FIPS 203 §3.3
  and §4.2.1 prohibit outright ("Implementations of ML-KEM shall not use floating-point
  arithmetic").
- **F203-11** — a random-bit-generation failure inside `Encaps` was indistinguishable
  from an invalid encapsulation key, whereas FIPS 203 Algorithm 20 steps 2–4 define it as
  a separate error condition.

Vendoring the minimal ML-KEM surface into `src/` is the only mechanism by which those
corrections actually ship to consumers of this SDK. Each modification is annotated inline
and covered by a regression test under `packages/core/src/vendor/ml-kem/__tests__/`.

`@noble/post-quantum` remains a dependency of this package. As of 2026-09-09 it no longer
provides X-Wing: `x-wing`'s embedded ML-KEM-768 ran the two defects above on every
encapsulation and decapsulation until then (see `docs/compliance/FIPS-203-MATRIX.md`
§3.10), because `@noble/post-quantum/hybrid.js` builds its `ml_kem768_x25519` preset from
that package's own unpatched `ml-kem.ts`, not from this vendored copy.
`packages/core/src/x-wing.ts` closes that gap by reconstructing the same preset from
`hybrid.js`'s public `combineKEMS`, `expandSeedXof` and `_ecdhKem` exports — generic
seed-expansion/composition glue with no ML-KEM arithmetic in it, so it did not need
vendoring — substituting this directory's `ml_kem768` for the npm-internal one.

What `@noble/post-quantum` still provides to this package: that combiner glue for
X-Wing, plus SLH-DSA and Falcon (neither implemented by this SDK yet). ML-DSA is vendored
separately, under `packages/core/src/vendor/ml-dsa/`, for the same reason as ML-KEM. Only
the ML-KEM entry points in `packages/core/src/algorithms.ts`, plus `x-wing.ts`'s
reconstructed preset, resolve to this vendored copy.

## Maintenance

When upgrading `@noble/post-quantum`, re-vendor rather than hand-merge:

1. Copy the three files again from the new version's `src/`.
2. Re-apply the modifications listed in each file header (they are small and localised).
3. Update the version, date and digests in this file.
4. Confirm `@noble/post-quantum/hybrid.js` still exports `combineKEMS`, `expandSeedXof`
   and `_ecdhKem` with the shapes `packages/core/src/x-wing.ts` relies on.
   `_ecdhKem`'s leading underscore is Noble's own convention for an internal API (its
   README says so explicitly), so the package does not owe these a semver guarantee — a
   removed or reshaped export is a real upgrade hazard, not a hypothetical one.
5. Run the full `packages/core` test suite. The equivalence and ACVP vector tests are the
   tripwire — do not adjust them to match new output. `x-wing.test.ts` is the tripwire
   specific to step 4: it fails if `hybrid.js`'s own `ml_kem768_x25519` preset ever
   diverges from `x-wing.ts`'s reconstruction of it.

## License

The following applies to `ml-kem.ts`, `_crystals.ts` and `utils.ts` in this directory.

```
The MIT License (MIT)

Copyright (c) 2024 Paul Miller (https://paulmillr.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
