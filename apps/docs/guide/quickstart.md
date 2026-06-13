# 5-minute quickstart

From zero to working post-quantum encryption.

## 1. Install

::: code-group

```bash [pnpm]
pnpm add @pqc-sdk/core
```

```bash [npm]
npm install @pqc-sdk/core
```

:::

Or initialize a full project with the CLI (config + development keys + example):

```bash
npx @pqc-sdk/cli init
```

## 2. Generate keys

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
//    ^?
```

With no options it generates **ML-KEM-768** (FIPS 203), the encryption
algorithm. Hover over `pair` to see the type: the algorithm travels in the
type system.

## 3. Encrypt

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
// ---cut---
const ciphertext = await pqc.encrypt('my first post-quantum secret', pair.publicKey);
```

Accepts a `string` (encoded as UTF-8) or a `Uint8Array`. The result is a single
self-contained `Uint8Array`: ML-KEM encapsulation + data encrypted with
AES-256-GCM.

## 4. Decrypt

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('my first post-quantum secret', pair.publicKey);
// ---cut---
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
console.log(new TextDecoder().decode(plaintext));
// "my first post-quantum secret"
```

If the ciphertext was tampered with, `decrypt` throws a `PqcError` with code
`DECRYPTION_FAILED` — it never returns corrupted data.

## Bonus: persisting keys

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
// ---cut---
const token = pqc.keys.serialize(pair.publicKey);
// "pqcv1.ml-kem-768.public.h1q3…" — base64url with metadata

const restored = pqc.keys.deserialize(token);
```

## Next steps

- [Hybrid KEM+AES encryption, explained](./hybrid-encryption) — what happens inside `encrypt`
- [Encrypting files](./encrypt-files) — the most common use case
- [Signing JWTs with ML-DSA](./sign-jwt) — post-quantum digital signatures
