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

## Two senses of "hybrid"

"Hybrid encryption" on this page means the classic **KEM-DEM** construction: a
public-key KEM (ML-KEM-768) agrees on a symmetric key, and a symmetric cipher
(AES-256-GCM) encrypts the data. ML-KEM-768's 32-byte shared secret is used
directly as the AES-256 key. This is the long-standing meaning of the term —
public-key to establish a key, symmetric to move the bytes — and the one TLS
uses.

It is **not** a classical+post-quantum hybrid. Today the SDK uses ML-KEM-768 on
its own as the post-quantum KEM; there is no classical algorithm (such as
X25519 or RSA) combined alongside it.

### Why a classical+PQC hybrid can matter

A classical+PQC hybrid runs two key-establishment algorithms and combines their
secrets, so the result stays secure as long as _either_ one holds. That is a
meaningful safety margin: ML-KEM is standardized but relatively new, and the
transition guidance from NIST and the IETF recommends running a
well-understood classical algorithm alongside a post-quantum one during the
migration period. The trade-off is larger ciphertexts and a second key
exchange.

`pqc.encrypt` does not provide this property today: if ML-KEM-768 were ever
broken, the confidentiality of these ciphertexts would not fall back to a
second algorithm.

### Roadmap

A classical+PQC hybrid mode (X25519 + ML-KEM-768) is planned. It will follow an
established combiner such as
[X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
rather than a homegrown construction, so the security argument is one that has
already been reviewed. There is no committed version or date yet, and the mode
will be additive — today's KEM-DEM `encrypt`/`decrypt` keeps working unchanged.

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
