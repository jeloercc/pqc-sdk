# Quickstart de 5 minutos

De cero a cifrado post-cuántico funcionando.

## 1. Instalar

::: code-group

```bash [pnpm]
pnpm add @pqc-sdk/core
```

```bash [npm]
npm install @pqc-sdk/core
```

:::

O inicializá un proyecto completo con el CLI (config + keys de desarrollo + ejemplo):

```bash
npx @pqc-sdk/cli init
```

## 2. Generar keys

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
//    ^?
```

Sin opciones genera **ML-KEM-768** (FIPS 203), el algoritmo de cifrado. Pasá el cursor
sobre `pair` para ver el tipo: el algoritmo viaja en el sistema de tipos.

## 3. Cifrar

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
// ---cut---
const ciphertext = await pqc.encrypt('mi primer secreto post-cuántico', pair.publicKey);
```

Acepta `string` (se codifica UTF-8) o `Uint8Array`. El resultado es un único
`Uint8Array` autocontenido: encapsulamiento ML-KEM + datos cifrados con AES-256-GCM.

## 4. Descifrar

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('mi primer secreto post-cuántico', pair.publicKey);
// ---cut---
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
console.log(new TextDecoder().decode(plaintext));
// "mi primer secreto post-cuántico"
```

Si el ciphertext fue manipulado, `decrypt` lanza un `PqcError` con código
`DECRYPTION_FAILED` — nunca devuelve datos corruptos.

## Bonus: persistir keys

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate();
// ---cut---
const token = pqc.keys.serialize(pair.publicKey);
// "pqcv1.ml-kem-768.public.h1q3…" — base64url con metadata

const restored = pqc.keys.deserialize(token);
```

## Siguientes pasos

- [Cifrado híbrido KEM+AES, explicado](./hybrid-encryption) — qué pasa adentro de `encrypt`
- [Cifrar archivos](./encrypt-files) — el caso de uso más común
- [Firmar JWTs con ML-DSA](./sign-jwt) — firmas digitales post-cuánticas
