# @pqc-sdk/core

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![bundle size](https://img.shields.io/bundlephobia/minzip/%40pqc-sdk%2Fcore)](https://bundlephobia.com/package/@pqc-sdk/core)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Criptografía post-cuántica para JS/TS con defaults seguros y cero configuración.
**ML-KEM-768** (FIPS 203) + AES-256-GCM para cifrado híbrido, **ML-DSA-65**
(FIPS 204) para firmas. Validado contra los test vectors oficiales NIST ACVP.

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

console.log(new TextDecoder().decode(plaintext), valid); // "secreto" true
```

## Compatibilidad

| Runtime            | Soporte | Notas                                         |
| ------------------ | ------- | --------------------------------------------- |
| Node 20+           | ✅      | ESM y CJS                                     |
| Cloudflare Workers | ✅      | Sin `nodejs_compat`; ~20 KB gzip en el bundle |
| Deno 2+            | ✅      | `npm:@pqc-sdk/core`                           |
| Bun                | ✅      |                                               |
| React Native       | ✅      | Requiere `react-native-get-random-values`     |
| Navegadores        | ✅      | Cualquier target ES2022 con WebCrypto         |

Sin WASM ni addons nativos: TypeScript puro sobre
[@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum).

## Benchmarks

Node 24, x86_64 (mensajes de 1 KB):

| Operación         | Tiempo     | Throughput |
| ----------------- | ---------- | ---------- |
| keygen ML-KEM-768 | 1,3 ms/op  | 768 ops/s  |
| encrypt           | 1,7 ms/op  | 585 ops/s  |
| decrypt           | 2,3 ms/op  | 440 ops/s  |
| keygen ML-DSA-65  | 4,8 ms/op  | 210 ops/s  |
| sign              | 20,2 ms/op | 50 ops/s   |
| verify            | 5,1 ms/op  | 195 ops/s  |

## Documentación

Documentación completa en **[jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**.

- [Quickstart de 5 minutos](https://jeloercc.github.io/pqc-sdk/guide/quickstart)
- [Cifrado híbrido KEM+AES, explicado](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption)
- [Compatibilidad detallada](https://jeloercc.github.io/pqc-sdk/compatibility)
- [Referencia de API](https://jeloercc.github.io/pqc-sdk/api/)

## Seguridad

- Nunca implementamos primitivas: ML-KEM/ML-DSA vienen de `@noble/post-quantum`
  y AES-GCM de `@noble/ciphers`.
- `@noble/post-quantum` no tiene aún auditoría independiente (self-audit
  04/2026). Como todo JS, sin garantías constant-time estrictas.
- Reportes de seguridad: abrí un issue privado o escribí al maintainer.

## Licencia

[MIT](./LICENSE)
