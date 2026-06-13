# Encrypting files

The most common use case: encrypting a file for someone who has an ML-KEM-768
key pair, so that only that person can open it.

## Setup: the recipient generates and shares their public key

```bash
npx @pqc-sdk/cli keygen --out keys/
# keys/ml-kem-768.public.pqc  → shared (mail, repo, wherever)
# keys/ml-kem-768.secret.pqc  → NEVER leaves the recipient's machine
```

## Encrypt (sender side)

```ts twoslash
import { readFile, writeFile } from 'node:fs/promises';
import { pqc } from '@pqc-sdk/core';

// The recipient's public key, received as serialized text
const publicKey = pqc.keys.deserialize(
  (await readFile('keys/ml-kem-768.public.pqc', 'utf8')).trim(),
);

const contents = await readFile('confidential-report.pdf');
const ciphertext = await pqc.encrypt(contents, publicKey as never);
await writeFile('confidential-report.pdf.pqc', ciphertext);
```

::: tip The `as never` cast
`deserialize` returns the wide `PqcKey` type because the algorithm is only
known at runtime. Validation is runtime: if the key is not an ML-KEM-768
public key, `encrypt` throws `PqcError('WRONG_ALGORITHM')`. In your code you
can wrap this in a helper that validates `key.algorithm` and returns the
narrow type.
:::

## Decrypt (recipient side)

```ts twoslash
import { readFile, writeFile } from 'node:fs/promises';
import { pqc } from '@pqc-sdk/core';

const secretKey = pqc.keys.deserialize(
  (await readFile('keys/ml-kem-768.secret.pqc', 'utf8')).trim(),
);

const ciphertext = await readFile('confidential-report.pdf.pqc');
const contents = await pqc.decrypt(new Uint8Array(ciphertext), secretKey as never);
await writeFile('confidential-report.pdf', contents);
```

If the `.pqc` file was altered in transit — even a single bit — `decrypt`
throws `DECRYPTION_FAILED` instead of returning a corrupted PDF: AES-GCM
authenticates the whole content.

## Error handling

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
      case 'INVALID_CIPHERTEXT': // not a .pqc file, or truncated
      case 'DECRYPTION_FAILED': // tampered with, or the key does not match
        console.error(error.message);
    }
  }
}
```

## Large files

`encrypt` operates in memory: for files of hundreds of MB consider encrypting
in chunks (each chunk is an independent `encrypt` with its own encapsulation)
or wait for the SDK's streaming API. The per-message overhead is 1118 bytes.
