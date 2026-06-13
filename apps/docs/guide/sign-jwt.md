# Signing JWTs with ML-DSA

Classic JWTs are signed with RS256 (RSA) or ES256 (ECDSA) — both become
deprecated around 2030 and disallowed in 2035 per NIST IR 8547. This guide
builds a JWT signed with **ML-DSA-65** (FIPS 204) using the SDK.

::: warning Standardization status
The `alg` registration for ML-DSA in JOSE is still in progress at the IETF
(`ML-DSA` draft for COSE/JOSE). In the meantime this pattern uses a custom
`alg` value — perfect for **internal** JWTs between your own services, which
is where migrating first makes sense today.
:::

## Issuing the token

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const b64url = (data: Uint8Array | string) => Buffer.from(data).toString('base64url');

const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

const header = { alg: 'ML-DSA-65', typ: 'JWT' };
const payload = {
  sub: 'user-42',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
const signature = await pqc.sign(signingInput, pair.secretKey);

const jwt = `${signingInput}.${b64url(signature)}`;
```

The ML-DSA-65 signature is **3309 bytes** (~4.4 KB in base64url). An RS256 JWT
is around 800 bytes: the post-quantum token is ~6x larger. It won't fit in
cookies with a 4 KB limit — use it in `Authorization` headers or
server-to-server tokens.

## Verifying the token

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
declare const jwt: string;
// ---cut---
const [headerB64, payloadB64, signatureB64] = jwt.split('.') as [string, string, string];

const valid = await pqc.verify(
  `${headerB64}.${payloadB64}`,
  new Uint8Array(Buffer.from(signatureB64, 'base64url')),
  pair.publicKey,
);

if (!valid) throw new Error('invalid token');

const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as {
  sub: string;
  exp: number;
};
if (payload.exp < Date.now() / 1000) throw new Error('expired token');
```

`verify` returns `false` for any altered or malformed signature — it never
throws because of a corrupted signature, so the validation flow stays linear.

## Isolating audiences with context strings

FIPS 204 defines _context strings_: the same key can sign different domains
without a token from one domain validating in another.

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
// ---cut---
const ctx = new TextEncoder().encode('auth-service:v1');

const signature = await pqc.sign('payload', pair.secretKey, { context: ctx });

await pqc.verify('payload', signature, pair.publicKey, { context: ctx }); // true
await pqc.verify('payload', signature, pair.publicKey); // false: different context
```

## Distributing the public key

The verification public key serializes and gets published like any JWKS:

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
// ---cut---
// On the issuer:
const published = pqc.keys.serialize(pair.publicKey);

// On each verifier:
const verificationKey = pqc.keys.deserialize(published);
```
