# Cifrado híbrido KEM+AES, explicado

`pqc.encrypt` parece una caja negra. No lo es — esto es exactamente lo que pasa adentro.

## El problema que resuelve

ML-KEM no es un cifrador de datos: es un **mecanismo de encapsulamiento de claves**
(KEM). No puede cifrar tu JSON de 2 MB; lo único que sabe hacer es acordar un
secreto de 32 bytes entre dos partes de forma resistente a computadoras cuánticas.

El patrón estándar (el mismo de TLS) es **híbrido**: el KEM acuerda el secreto,
y un cifrador simétrico rápido — AES-256-GCM — cifra los datos con ese secreto.

## Paso a paso

```
encrypt(data, publicKey):

  1. ML-KEM-768.encapsulate(publicKey)
       → cipherText (1088 bytes)      lo que viaja
       → sharedSecret (32 bytes)      NUNCA viaja

  2. nonce = random(12 bytes)

  3. sealed = AES-256-GCM(key = sharedSecret, nonce).encrypt(data)
       → incluye tag de autenticación (16 bytes)

  4. resultado = [versión|alg|cipherText|nonce|sealed]
```

El receptor invierte el proceso: `decapsulate(cipherText, secretKey)` reconstruye
el **mismo** `sharedSecret` de 32 bytes, y AES-GCM descifra y **verifica
integridad**. Un solo bit alterado y el tag no valida: `decrypt` lanza
`PqcError('DECRYPTION_FAILED')`.

## Por qué estas decisiones

- **El shared secret de ML-KEM se usa directo como key AES-256.** FIPS 203
  garantiza que es uniformemente aleatorio, así que no necesita KDF intermedio.
- **GCM** aporta confidencialidad _y_ autenticación en una pasada — sin
  cifrar-luego-firmar manual, sin oráculos de padding.
- **Nonce aleatorio por mensaje**: cifrar dos veces lo mismo produce ciphertexts
  distintos.
- **Overhead fijo**: 1118 bytes por mensaje (2 header + 1088 KEM + 12 nonce +
  16 tag), sea el payload de 1 byte o de 100 MB.

## En código

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();

const a = await pqc.encrypt('mismo mensaje', pair.publicKey);
const b = await pqc.encrypt('mismo mensaje', pair.publicKey);
console.log(a.length === b.length); // true — overhead fijo
// pero a ≠ b: encapsulamiento y nonce frescos en cada llamada
```

## Qué NO hace

- **No autentica al emisor.** Cualquiera con tu public key puede cifrarte mensajes.
  Si necesitás saber quién lo mandó, combiná con [firmas ML-DSA](./sign-jwt).
- **No protege la secret key.** Guardala como cualquier secreto (KMS, env vars
  cifradas — y fuera de git).
