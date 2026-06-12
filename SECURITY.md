# Política de seguridad

## Reportar una vulnerabilidad

**No abras un issue público.** Usá el reporte privado de GitHub:

1. Andá a [Security → Report a vulnerability](https://github.com/jeloercc/pqc-sdk/security/advisories/new).
2. Describí el problema: versión afectada, impacto, y pasos o PoC para reproducirlo.

Qué podés esperar:

- **Acuse de recibo dentro de las 72 horas.**
- Evaluación y plan de fix (o descarte justificado) dentro de los 14 días.
- Divulgación coordinada: publicamos el advisory y el crédito al reporter
  (si lo querés) junto con la versión parcheada.

## Versiones soportadas

| Versión      | Soporte                          |
| ------------ | -------------------------------- |
| Última `0.x` | ✅ Fixes de seguridad            |
| Anteriores   | ❌ Actualizá a la última versión |

Mientras el proyecto esté en `0.x`, los fixes de seguridad salen solo sobre la
última versión publicada de `@pqc-sdk/core` y `@pqc-sdk/cli`.

## Alcance

**En alcance:** el código de este repo — la API de `@pqc-sdk/core` (cifrado
híbrido, firmas, serialización de keys), el CLI, y cualquier uso incorrecto que
hagamos de las primitivas (nonces, derivación, manejo de material sensible).

**Fuera de alcance (reportar upstream):** las primitivas en sí. ML-KEM y
ML-DSA vienen de [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
y AES-256-GCM de [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers);
vulnerabilidades en esas implementaciones se reportan a sus maintainers.

## Modelo de amenazas: límites conocidos

Para que evalúes si el SDK aplica a tu caso:

- `@noble/post-quantum` no tiene todavía auditoría independiente
  (self-audit 04/2026).
- Como toda implementación en JavaScript, no hay garantías estrictas de
  ejecución en tiempo constante; ataques de side-channel locales quedan fuera
  del modelo de amenazas.
- Las keys generadas por `pqc init` son de desarrollo y el CLI lo advierte:
  no las uses en producción.
