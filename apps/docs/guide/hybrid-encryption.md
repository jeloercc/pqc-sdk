# Hybrid KEM+AES encryption, explained

`pqc.encrypt` looks like a black box. It isn't — this is exactly what happens inside.

## The problem it solves

ML-KEM is not a data cipher: it is a **key encapsulation mechanism** (KEM). It
cannot encrypt your 2 MB JSON; the only thing it knows how to do is agree on a
32-byte secret between two parties in a way that resists quantum computers.

The standard pattern (the same one TLS uses) is **hybrid**: the KEM agrees on
the secret, and a fast symmetric cipher — AES-256-GCM — encrypts the data with
that secret.

## Step by step

```
encrypt(data, publicKey):

  1. ML-KEM-768.encapsulate(publicKey)
       → cipherText (1088 bytes)      what travels
       → sharedSecret (32 bytes)      NEVER travels

  2. nonce = random(12 bytes)

  3. sealed = AES-256-GCM(key = sharedSecret, nonce).encrypt(data)
       → includes the authentication tag (16 bytes)

  4. result = [version|alg|cipherText|nonce|sealed]
```

The recipient reverses the process: `decapsulate(cipherText, secretKey)`
reconstructs the **same** 32-byte `sharedSecret`, and AES-GCM decrypts and
**verifies integrity**. A single flipped bit and the tag fails to validate:
`decrypt` throws `PqcError('DECRYPTION_FAILED')`.

## Why these decisions

- **ML-KEM's shared secret is used directly as the AES-256 key.** FIPS 203
  guarantees it is uniformly random, so no intermediate KDF is needed.
- **GCM** provides confidentiality _and_ authentication in one pass — no
  manual encrypt-then-sign, no padding oracles.
- **Random nonce per message**: encrypting the same thing twice produces
  different ciphertexts.
- **Fixed overhead**: 1118 bytes per message (2 header + 1088 KEM + 12 nonce +
  16 tag), whether the payload is 1 byte or 100 MB.

## In code

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();

const a = await pqc.encrypt('same message', pair.publicKey);
const b = await pqc.encrypt('same message', pair.publicKey);
console.log(a.length === b.length); // true — fixed overhead
// but a ≠ b: fresh encapsulation and nonce on every call
```

## What it does NOT do

- **It does not authenticate the sender.** Anyone with your public key can
  encrypt messages to you. If you need to know who sent it, combine with
  [ML-DSA signatures](./sign-jwt).
- **It does not protect the secret key.** Store it like any secret (KMS,
  encrypted env vars — and out of git).
