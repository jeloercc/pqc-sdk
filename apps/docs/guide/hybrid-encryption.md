# Hybrid KEM+AES encryption, explained

`pqc.encrypt` looks like a black box. It isn't — this is exactly what happens inside.

## The problem it solves

ML-KEM is not a data cipher: it is a **key encapsulation mechanism** (KEM). It
cannot encrypt your 2 MB JSON; the only thing it knows how to do is agree on a
32-byte secret between two parties in a way that resists quantum computers.

The standard pattern (the same one TLS uses) is **hybrid**: the KEM agrees on
the secret, and a fast symmetric cipher — AES-256-GCM — encrypts the data with
that secret.

## Step by step: `ml-kem-768` (envelope v1)

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

## Step by step: `x-wing` (envelope v2)

Same shape, one extra combining step because two KEMs run instead of one:

```
encrypt(data, publicKey):

  1. XWing.encapsulate(publicKey)         # runs X25519 AND ML-KEM-768 internally
       → cipherText = ct_M(1088) ‖ ct_X(32)   → 1120 bytes, what travels
       → sharedSecret (32 bytes)              → SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)
                                                 NEVER travels

  2. nonce = random(12 bytes)

  3. sealed = AES-256-GCM(key = sharedSecret, nonce).encrypt(data)
       → includes the authentication tag (16 bytes)

  4. result = [version|alg|cipherText|nonce|sealed]
```

The `sharedSecret` X-Wing returns is **already** the draft's combiner output —
a SHA3-256 hash over both component secrets, the ciphertext, and the public
key, with a fixed domain-separation label. The SDK uses it directly as the
AES-256 key, exactly like `ml-kem-768`'s secret, because the combiner already
_is_ the key derivation (see "Why these decisions").

## Why these decisions

- **The KEM's shared secret is used directly as the AES-256 key**, for both
  algorithms. FIPS 203 guarantees ML-KEM-768's shared secret is uniformly
  random; X-Wing's shared secret is its own combiner output (SHA3-256 with
  domain separation) — either way, no additional KDF layer is added on top.
- **GCM** provides confidentiality _and_ authentication in one pass — no
  manual encrypt-then-sign, no padding oracles.
- **Random nonce per message**: encrypting the same thing twice produces
  different ciphertexts.
- **Fixed overhead**: 1118 bytes per message for `ml-kem-768` (2 header + 1088
  KEM + 12 nonce + 16 tag), **1150 bytes for `x-wing`** (2 header + 1120
  hybrid ciphertext + 12 nonce + 16 tag) — 32 bytes more, the size of the
  X25519 ephemeral share (`ct_X`) — whether the payload is 1 byte or 100 MB.

## Two senses of "hybrid"

"Hybrid encryption" on this page means the classic **KEM-DEM** construction: a
public-key KEM agrees on a symmetric key, and a symmetric cipher
(AES-256-GCM) encrypts the data. This is the long-standing meaning of the
term — public-key to establish a key, symmetric to move the bytes — and the
one TLS uses. Both algorithms below follow it.

That is a **different axis** from **classical+post-quantum hybrid**: running
two key-establishment algorithms and combining their secrets, so the result
stays secure as long as _either_ one holds. The SDK offers this as a second,
opt-in KEM:

- **`ml-kem-768`** (default): ML-KEM-768 (FIPS 203) alone as the KEM. Envelope
  `pqcenc.v1`.
- **`x-wing`** (opt-in): X25519 + ML-KEM-768, combined per
  [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
  an established construction with a
  [formal security analysis](https://eprint.iacr.org/2024/039) — not a
  homegrown combiner. Envelope `pqcenc.v2`.

Both are selected purely by which key you pass — same `pqc.encrypt`/
`pqc.decrypt` signature, no mode flag:

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const kemOnly = await pqc.keys.generate(); // ml-kem-768 → pqcenc.v1
const hybrid = await pqc.keys.generate({ algorithm: 'x-wing' }); // → pqcenc.v2

await pqc.encrypt('data', kemOnly.publicKey); // v1 envelope
await pqc.encrypt('data', hybrid.publicKey); // v2 envelope
// pqc.decrypt reads the leading version byte and picks the matching path —
// no need to track which algorithm produced a given ciphertext.
```

## Choosing an algorithm

|                                               | `ml-kem-768` (default) | `x-wing` (opt-in)                 |
| --------------------------------------------- | ---------------------- | --------------------------------- |
| Security if ML-KEM-768 alone were ever broken | Confidentiality lost   | Still confidential (X25519 holds) |
| Overhead per message                          | 1118 bytes + plaintext | 1150 bytes + plaintext (+32 B)    |
| Public key                                    | 1184 bytes             | 1216 bytes                        |
| Secret key                                    | 2400 bytes             | 32 bytes (a seed)                 |
| Relative speed (this SDK's bench)             | baseline               | ~3–6× slower per operation        |

**Use `x-wing`** for data that must stay confidential for years — archives,
backups, anything with a long secrecy requirement — where the extra 32 bytes
and the slower KEM operations are a small price for not depending on a single,
relatively new algorithm. This mirrors the industry's current default for new
protocols: TLS 1.3's `X25519MLKEM768`, Signal's PQXDH, and Apple's PQ3 all
combine a classical KEM with a post-quantum one rather than betting on either
alone.

**`ml-kem-768` remains the SDK default** (`pqc.keys.generate()` with no
arguments) through 1.x for two reasons: changing the no-arg return type would
be a breaking change for TypeScript consumers, and a peer still on ≤0.4.x
cannot decrypt a `pqcenc.v2` envelope or parse an `x-wing` key token — a mixed
deployment needs its readers upgraded before its writers switch. The default
flips to `x-wing` at v1.0 (the next breaking-change milestone), with a
documented migration path (`{ algorithm: 'ml-kem-768' }` to keep today's
behavior).

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
