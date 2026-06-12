# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Criptografía post-cuántica para JS/TS con defaults seguros y cero configuración:
**ML-KEM-768** (FIPS 203) + AES-256-GCM para cifrado híbrido y **ML-DSA-65**
(FIPS 204) para firmas, validado contra los test vectors oficiales NIST ACVP.
El objetivo: que agregues cifrado post-cuántico a tu app en 30 minutos.

## Quickstart

```bash
npm install @pqc-sdk/core
```

```ts
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('secreto', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('documento', signer.secretKey);
const valid = await pqc.verify('documento', signature, signer.publicKey);
```

O arrancá un proyecto entero con el CLI:

```bash
npx @pqc-sdk/cli init
```

**Documentación completa en [jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**:
[quickstart de 5 minutos](https://jeloercc.github.io/pqc-sdk/guide/quickstart),
[cifrado híbrido explicado](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption),
[compatibilidad por runtime](https://jeloercc.github.io/pqc-sdk/compatibility) y
[referencia de API](https://jeloercc.github.io/pqc-sdk/api/).

## Paquetes

| Paquete                                                        | Qué hace                                                                         |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | El SDK: cifrado híbrido, firmas, manejo de keys. Node 20+, Deno, Workers, RN.    |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init` / `keygen` / `audit`: scaffolding, keys y detección de crypto legacy. |

## Estructura del monorepo

```
packages/core    @pqc-sdk/core — el SDK (TypeScript, ESM + CJS)
packages/cli     @pqc-sdk/cli — CLI construido sobre core
apps/docs        sitio de documentación (VitePress + typedoc)
examples/        proyectos de ejemplo: node, deno, cloudflare-workers
docs/            documentación fuente del repo (compatibilidad)
```

Turborepo + pnpm workspaces. Ver [CONTRIBUTING.md](./CONTRIBUTING.md) para
correr el repo localmente.

## Seguridad

Nunca implementamos primitivas criptográficas: ML-KEM/ML-DSA vienen de
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) y
AES-GCM de [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
Para reportar una vulnerabilidad, ver [SECURITY.md](./SECURITY.md) — por favor
no abras issues públicos.

## Licencia

[MIT](./LICENSE)
