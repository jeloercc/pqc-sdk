# Cifrar archivos

El caso de uso más común: cifrar un archivo para alguien que tiene un par de keys
ML-KEM-768, de modo que solo esa persona pueda abrirlo.

## Preparación: el receptor genera y comparte su public key

```bash
npx @pqc-sdk/cli keygen --out keys/
# keys/ml-kem-768.public.pqc  → se comparte (mail, repo, donde sea)
# keys/ml-kem-768.secret.pqc  → NO sale de la máquina del receptor
```

## Cifrar (lado emisor)

```ts twoslash
import { readFile, writeFile } from 'node:fs/promises';
import { pqc } from '@pqc-sdk/core';

// La public key del receptor, recibida como texto serializado
const publicKey = pqc.keys.deserialize(
  (await readFile('keys/ml-kem-768.public.pqc', 'utf8')).trim(),
);

const contents = await readFile('informe-confidencial.pdf');
const ciphertext = await pqc.encrypt(contents, publicKey as never);
await writeFile('informe-confidencial.pdf.pqc', ciphertext);
```

::: tip El cast `as never`
`deserialize` devuelve el tipo amplio `PqcKey` porque el algoritmo se conoce
recién en runtime. La validación es runtime: si la key no es ML-KEM-768 pública,
`encrypt` lanza `PqcError('WRONG_ALGORITHM')`. En tu código podés encapsular esto
en un helper que valide `key.algorithm` y devuelva el tipo angosto.
:::

## Descifrar (lado receptor)

```ts twoslash
import { readFile, writeFile } from 'node:fs/promises';
import { pqc } from '@pqc-sdk/core';

const secretKey = pqc.keys.deserialize(
  (await readFile('keys/ml-kem-768.secret.pqc', 'utf8')).trim(),
);

const ciphertext = await readFile('informe-confidencial.pdf.pqc');
const contents = await pqc.decrypt(new Uint8Array(ciphertext), secretKey as never);
await writeFile('informe-confidencial.pdf', contents);
```

Si el archivo `.pqc` fue alterado en tránsito — aunque sea un bit — `decrypt`
lanza `DECRYPTION_FAILED` en vez de devolver un PDF corrupto: AES-GCM autentica
todo el contenido.

## Manejo de errores

```ts twoslash
import { pqc, PqcError } from '@pqc-sdk/core';
declare const ciphertext: Uint8Array;
declare const secretKey: import('@pqc-sdk/core').SecretKey<'ml-kem-768'>;
// ---cut---
try {
  await pqc.decrypt(ciphertext, secretKey);
} catch (error) {
  if (error instanceof PqcError) {
    switch (error.code) {
      case 'INVALID_CIPHERTEXT': // no es un archivo .pqc o está truncado
      case 'DECRYPTION_FAILED': // manipulado, o la key no corresponde
        console.error(error.message);
    }
  }
}
```

## Archivos grandes

`encrypt` opera en memoria: para archivos de cientos de MB considerá cifrar por
chunks (cada chunk es un `encrypt` independiente con su propio encapsulamiento) o
esperá la API de streaming del SDK. El overhead por mensaje es de 1118 bytes.
