# Firmar JWTs con ML-DSA

Los JWT clásicos se firman con RS256 (RSA) o ES256 (ECDSA) — ambos quedan
deprecados hacia 2030 y prohibidos en 2035 según NIST IR 8547. Esta guía arma un
JWT firmado con **ML-DSA-65** (FIPS 204) usando el SDK.

::: warning Estado de la estandarización
El registro de `alg` para ML-DSA en JOSE todavía está en proceso en el IETF
(draft `ML-DSA` para COSE/JOSE). Mientras tanto este patrón usa un valor de
`alg` propio — perfecto para JWTs **internos** entre tus propios servicios,
que es donde hoy tiene sentido migrar primero.
:::

## Emitir el token

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

La firma ML-DSA-65 mide **3309 bytes** (~4,4 KB en base64url). Un JWT RS256 ronda
los 800 bytes: el token post-cuántico es ~6x más grande. Para cookies con límite
de 4 KB no entra — usalo en headers `Authorization` o tokens server-to-server.

## Verificar el token

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

if (!valid) throw new Error('token inválido');

const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as {
  sub: string;
  exp: number;
};
if (payload.exp < Date.now() / 1000) throw new Error('token expirado');
```

`verify` devuelve `false` ante cualquier firma alterada o malformada — nunca
lanza por una firma corrupta, así que el flujo de validación queda lineal.

## Aislar audiencias con context strings

FIPS 204 define _context strings_: la misma key puede firmar dominios distintos
sin que un token de un dominio valide en otro.

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
// ---cut---
const ctx = new TextEncoder().encode('auth-service:v1');

const signature = await pqc.sign('payload', pair.secretKey, { context: ctx });

await pqc.verify('payload', signature, pair.publicKey, { context: ctx }); // true
await pqc.verify('payload', signature, pair.publicKey); // false: otro contexto
```

## Distribuir la public key

La public key de verificación se serializa y publica como cualquier JWKS:

```ts twoslash
import { pqc } from '@pqc-sdk/core';
const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
// ---cut---
// En el emisor:
const published = pqc.keys.serialize(pair.publicKey);

// En cada verificador:
const verificationKey = pqc.keys.deserialize(published);
```
