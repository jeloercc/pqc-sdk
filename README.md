# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Post-quantum cryptography for JS/TS with safe defaults and zero configuration:
**ML-KEM-768** (FIPS 203) + AES-256-GCM for hybrid encryption and **ML-DSA-65**
(FIPS 204) for signatures, validated against the official NIST ACVP test
vectors. The goal: add post-quantum encryption to your app in 30 minutes.

> Here "hybrid encryption" means the classic KEM-DEM scheme — ML-KEM-768
> encapsulating an AES-256-GCM key — **not** a classical+post-quantum hybrid.
> A combined X25519 + ML-KEM-768 mode is on the roadmap; see
> [hybrid encryption explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption).

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
[runtime compatibility](https://jeloercc.github.io/pqc-sdk/compatibility) and
[API reference](https://jeloercc.github.io/pqc-sdk/api/).

## Packages

| Package                                                        | What it does                                                                              |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | The SDK: hybrid encryption, signatures, key handling. Node 20+, Deno, Workers, RN.        |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init` / `keygen` / `audit`: scaffolding, keys and heuristic legacy-crypto detection. |

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

## Security

We never implement cryptographic primitives: ML-KEM/ML-DSA come from
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
AES-GCM from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
To report a vulnerability, see [SECURITY.md](./SECURITY.md) — please do not
open public issues.

## License

[MIT](./LICENSE)
