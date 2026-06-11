# ¿Por qué PQC ahora?

La respuesta corta: porque los deadlines regulatorios ya empezaron, y porque los
datos cifrados hoy con RSA/ECC pueden cosecharse hoy y descifrarse cuando exista
una computadora cuántica relevante (_harvest now, decrypt later_).

## El problema

Un algoritmo cuántico de 1994 (Shor) rompe toda la criptografía de clave pública
desplegada: RSA, ECDSA, ECDH, Ed25519. No existe todavía una computadora cuántica
capaz de ejecutarlo a escala — pero cualquier dato con vida útil larga (historias
clínicas, secretos industriales, comunicaciones diplomáticas) capturado hoy queda
expuesto retroactivamente el día que exista.

NIST estandarizó la respuesta en agosto de 2024: **FIPS 203 (ML-KEM)** para
intercambio de claves, **FIPS 204 (ML-DSA)** y **FIPS 205 (SLH-DSA)** para firmas.
Son los algoritmos que implementa este SDK.

## Los deadlines

### CNSA 2.0 (NSA, sistemas de seguridad nacional de EE. UU.)

| Fecha          | Hito                                                              |
| -------------- | ----------------------------------------------------------------- |
| **1 ene 2027** | Toda **nueva adquisición** para NSS debe soportar CNSA 2.0        |
| 2030           | Equipamiento de red (VPNs, routers) exclusivamente PQC            |
| 2031           | Uso obligatorio en todas las categorías cubiertas                 |
| 2033           | Sistemas operativos y aplicaciones custom exclusivamente PQC      |
| 2035           | Migración completa (NSM-10): cero algoritmos cuántico-vulnerables |

CNSA 2.0 exige los parámetros más altos (ML-KEM-1024, ML-DSA-87). Para uso
general fuera de NSS, NIST avala los parámetros que usa este SDK por defecto
(ML-KEM-768, ML-DSA-65), que son el balance estándar seguridad/tamaño.

### NIST IR 8547 (todo el gobierno federal de EE. UU., y de facto la industria)

- **2030–2031**: RSA, ECDSA, ECDH y DSA quedan **deprecados**.
- **2035**: quedan **prohibidos** en sistemas federales.

Australia (ASD) es más agresiva: prohíbe la criptografía clásica en sistemas
gubernamentales **después de 2030**. La UE recomendó a los estados miembro tener
planes de transición y los casos de alto riesgo migrados hacia 2030.

## Qué significa para tu app

1. **Si tus datos deben seguir siendo secretos en 2035**, cifrarlos hoy con RSA/ECDH
   ya es deuda técnica con interés compuesto. El intercambio de claves es lo primero
   a migrar (es lo vulnerable a _harvest now, decrypt later_).
2. **Si vendés al sector público** (EE. UU., UE, Australia), los requisitos de
   compras con PQC ya están entrando en los pliegos — en EE. UU., desde enero de 2027.
3. **Las firmas urgen menos** (un atacante necesita la computadora cuántica _antes_
   de que expire lo firmado), pero todo lo que firme con vida útil larga — firmware,
   actualizaciones de software, certificados raíz — ya está migrando.

## Empezar hoy cuesta poco

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('listo para 2035', pair.publicKey);
```

Y para saber cuánto crypto pre-cuántico tiene tu codebase hoy:

```bash
npx @pqc-sdk/cli audit
```

Fuentes: [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) ·
[NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) ·
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) ·
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
