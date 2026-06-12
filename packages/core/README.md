# @pqc-sdk/core

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![bundle size](https://img.shields.io/bundlephobia/minzip/%40pqc-sdk%2Fcore)](https://bundlephobia.com/package/@pqc-sdk/core)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Post-quantum cryptography for JS/TS with safe defaults and zero configuration.
**ML-KEM-768** (FIPS 203) + AES-256-GCM for hybrid encryption, **ML-DSA-65**
(FIPS 204) for signatures. Validated against the official NIST ACVP test
vectors.

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

console.log(new TextDecoder().decode(plaintext), valid); // "secret" true
```

## Compatibility

| Runtime            | Support | Notes                                     |
| ------------------ | ------- | ----------------------------------------- |
| Node 20+           | ✅      | ESM and CJS                               |
| Cloudflare Workers | ✅      | No `nodejs_compat`; ~20 KB gzip in bundle |
| Deno 2+            | ✅      | `npm:@pqc-sdk/core`                       |
| Bun                | ✅      |                                           |
| React Native       | ✅      | Requires `react-native-get-random-values` |
| Browsers           | ✅      | Any ES2022 target with WebCrypto          |

No WASM or native addons: pure TypeScript on top of
[@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum).

## Benchmarks

Node 24, x86_64 (1 KB messages):

| Operation         | Time       | Throughput |
| ----------------- | ---------- | ---------- |
| keygen ML-KEM-768 | 1.3 ms/op  | 768 ops/s  |
| encrypt           | 1.7 ms/op  | 585 ops/s  |
| decrypt           | 2.3 ms/op  | 440 ops/s  |
| keygen ML-DSA-65  | 4.8 ms/op  | 210 ops/s  |
| sign              | 20.2 ms/op | 50 ops/s   |
| verify            | 5.1 ms/op  | 195 ops/s  |

## Documentation

Full documentation at **[jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**.

- [5-minute quickstart](https://jeloercc.github.io/pqc-sdk/guide/quickstart)
- [Hybrid KEM+AES encryption, explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption)
- [Detailed compatibility](https://jeloercc.github.io/pqc-sdk/compatibility)
- [API reference](https://jeloercc.github.io/pqc-sdk/api/)

## Security

- We never implement primitives: ML-KEM/ML-DSA come from
  `@noble/post-quantum` and AES-GCM from `@noble/ciphers`.
- `@noble/post-quantum` has no independent audit yet (self-audit 04/2026).
  As with all JS, there are no strict constant-time guarantees.
- Security reports: see [SECURITY.md](https://github.com/jeloercc/pqc-sdk/blob/main/SECURITY.md) —
  please do not open public issues.

## License

[MIT](./LICENSE)
