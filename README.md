# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Post-quantum cryptography for JS/TS with safe defaults and zero configuration:
**ML-KEM-768** (FIPS 203) + AES-256-GCM for encryption, an optional
**X-Wing** hybrid mode (X25519 + ML-KEM-768, opt-in) for defense-in-depth on
long-term data, **streaming encryption** for files too large to hold in
memory, and **ML-DSA-65** (FIPS 204) for signatures — all validated against
the official NIST ACVP / draft test vectors. The goal: add post-quantum
encryption to your app in 30 minutes.

> `pqc.keys.generate()` still returns ML-KEM-768 by default. Pass
> `{ algorithm: 'x-wing' }` to get the classical+post-quantum hybrid KEM
> instead — recommended for data that must stay confidential for years, per
> the same industry consensus behind TLS's `X25519MLKEM768` and Signal's
> PQXDH. See
> [hybrid encryption explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption)
> for when to choose which.

## Quickstart

```bash
npm install @pqc-sdk/core
```

```ts
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('secret', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('document', signer.secretKey);
const valid = await pqc.verify('document', signature, signer.publicKey);
```

Or bootstrap a whole project with the CLI:

```bash
npx @pqc-sdk/cli init
```

**Full documentation at [jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**:
[5-minute quickstart](https://jeloercc.github.io/pqc-sdk/guide/quickstart),
[hybrid encryption explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption),
[streaming large files](https://jeloercc.github.io/pqc-sdk/guide/streaming-encryption),
[runtime compatibility](https://jeloercc.github.io/pqc-sdk/compatibility) and
[API reference](https://jeloercc.github.io/pqc-sdk/api/).

## Packages

| Package                                                        | What it does                                                                                                                                          |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | The SDK: hybrid encryption, signatures, key handling. Node 20+, Deno, Workers, RN.                                                                    |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init` / `keygen` / `encrypt` / `decrypt` / `audit`: scaffolding, keys, file encryption, and a heuristic (non-exhaustive) scan for legacy crypto. |

## Monorepo structure

```
packages/core    @pqc-sdk/core — the SDK (TypeScript, ESM + CJS)
packages/cli     @pqc-sdk/cli — CLI built on top of core
apps/docs        documentation site (VitePress + typedoc)
examples/        example projects: node, deno, cloudflare-workers, hermes-standalone
docs/            repo source documentation (compatibility)
```

Turborepo + pnpm workspaces. See [CONTRIBUTING.md](./CONTRIBUTING.md) to run
the repo locally.

## How this is verified

We never implement cryptographic primitives: ML-KEM/ML-DSA come from
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
AES-GCM from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
That means the interesting risk is **not** in the primitives — it is in the
layers this SDK does own: the envelope format, key serialization, nonce
derivation, and fail-closed behaviour on malformed input. Those are what the
following test suites exist to cover, and each one is a file you can read:

| Layer                         | How it is verified                                                                                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Primitive correctness         | Official **NIST ACVP vectors** for ML-KEM-768 and ML-DSA-65, plus the X-Wing draft's Appendix C vectors — [`nist-vectors.test.ts`](./packages/core/src/nist-vectors.test.ts), [`xwing-vectors.test.ts`](./packages/core/src/xwing-vectors.test.ts)                |
| Wire format stability         | **Golden serialization vectors** for every envelope version (v1, v2, streaming), regenerated only behind an acknowledged breaking change — [`src/vectors/`](./packages/core/src/vectors/), [`golden-vectors.test.ts`](./packages/core/src/golden-vectors.test.ts) |
| Parser hostility              | **Fuzzing** of `keys.deserialize` against arbitrary and hand-picked hostile input, asserting it always fails closed — [`deserialize-fuzz.test.ts`](./packages/core/src/deserialize-fuzz.test.ts)                                                                  |
| Roundtrip + tamper invariants | **Property-based tests** (`fast-check`): decrypt(encrypt(x)) === x for arbitrary payloads, and any single-byte tamper fails closed — [`properties.test.ts`](./packages/core/src/properties.test.ts)                                                               |
| Streaming envelope            | **Mutation matrix** tampering every region independently — truncation, reorder, duplication, cross-stream splice, final-flag games — each asserting the documented `PqcError` code — [`stream-mutations.test.ts`](./packages/core/src/stream-mutations.test.ts)   |
| Format specification          | The normative byte layout, so the tests above check an intent rather than the current output — [`docs/serialization-format.md`](./docs/serialization-format.md)                                                                                                   |
| Review                        | Pre-launch findings report ([`docs/AUDIT-2026-06.md`](./docs/AUDIT-2026-06.md)) and a source-level security review ([`docs/SECURITY-REVIEW-2026-06.md`](./docs/SECURITY-REVIEW-2026-06.md))                                                                       |
| Runtime claims                | Node, Deno, Cloudflare Workers, Hermes and a physical React Native device — each ✅ only after the roundtrip actually ran there — [`docs/compatibility.md`](./docs/compatibility.md)                                                                              |

Coverage floor is 90%; the suite currently runs ~297 tests across both
packages. Run it yourself with `pnpm turbo run lint test build --force`.

**What these reviews are not.** `docs/AUDIT-2026-06.md` and
`docs/SECURITY-REVIEW-2026-06.md` are internal, AI-assisted reviews. They are
**not** an independent third-party cryptographic audit, and the SDK does not
claim to be audited. `@noble/post-quantum` itself has no independent audit yet
either (self-audit 04/2026).

**Known limitation worth reading before you adopt this: there is no memory
zeroization.** Shared secrets, decrypted plaintext and secret-key bytes are
not wiped after use — JavaScript offers no reliable primitive for it and
`@noble` does not zeroize either, so it is an ecosystem limitation this SDK
cannot fully close. The full threat model, including the absence of
constant-time guarantees, is in [SECURITY.md](./SECURITY.md).

To report a vulnerability, see [SECURITY.md](./SECURITY.md) — please do not
open public issues.

## License

[MIT](./LICENSE)
