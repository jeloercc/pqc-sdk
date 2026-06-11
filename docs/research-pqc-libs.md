# Investigación: librerías PQC para JS/TS (junio 2026)

Comparación de bases criptográficas candidatas para el SDK.
Conclusión: **usar `@noble/post-quantum` como base**.

## Comparación

| Criterio           | @noble/post-quantum                               | mlkem (dajiaji)                            | @oqs/liboqs-js (WASM)                                                       | liboqs-node (nativo)   |
| ------------------ | ------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------- | ---------------------- |
| Última publicación | v0.6.1 · abr 2026                                 | v2.7.0 · mar 2026                          | v0.15.1 · feb 2026                                                          | v0.1.0 · 2022 (muerto) |
| Descargas/semana   | ~122.000                                          | ~7.800                                     | ~650                                                                        | ~280                   |
| ML-KEM (FIPS 203)  | ✅ final                                          | ✅ final                                   | ✅ final                                                                    | Kyber pre-estándar     |
| ML-DSA (FIPS 204)  | ✅ final                                          | ❌ solo KEM                                | ✅ final                                                                    | Dilithium pre-estándar |
| SLH-DSA (FIPS 205) | ✅ final                                          | ❌                                         | ✅ final                                                                    | SPHINCS+ pre-estándar  |
| Cloudflare Workers | ✅                                                | ✅                                         | Posible, no documentado                                                     | ❌ (addon nativo)      |
| React Native       | ✅ (polyfill getRandomValues)                     | Probable (puro TS)                         | ❌ (WASM en Hermes)                                                         | ❌                     |
| Deno / Bun         | ✅ (JSR)                                          | ✅                                         | ✅                                                                          | ❌                     |
| Bundle             | ~16 KB gzip (todo)                                | Pequeño (puro TS, tree-shakable)           | 80–500 KB WASM por algoritmo                                                | N/A                    |
| Dependencias       | Solo @noble/\* (mismo autor)                      | Cero                                       | liboqs compilado                                                            | node-pre-gyp, etc.     |
| Auditoría          | Self-audit 0.6.1; sin auditoría independiente aún | Sin auditoría; pasa KATs (NIST, C2SP/CCTV) | Hereda liboqs (bien revisado, "experimental, not for production" según OQS) | —                      |

## Notas por librería

### @noble/post-quantum (recomendada)

- Cubre exactamente los 3 algoritmos del CLAUDE.md (ML-KEM-768, ML-DSA-65, SLH-DSA) con los FIPS finales, en un solo paquete TypeScript auditable.
- Corre en todos los targets del proyecto: Node 20+, Workers, Deno y React Native (este último necesita polyfill de `crypto.getRandomValues`, p. ej. `react-native-get-random-values`).
- Caveats a documentar en el SDK: sin protecciones constant-time garantizadas (limitación de todo JS con JIT) y sin auditoría independiente todavía (self-audit en 0.6.1, abr 2026). Falcon incluido es Round 3, no FN-DSA final — no usarlo.
- Diseñar la capa de proveedores del SDK (`packages/core/src/providers/`) para poder swapear el backend si más adelante conviene WASM/nativo en algún runtime.

### mlkem / crystals-kyber-js (dajiaji)

- Excelente implementación pura TS de ML-KEM (afirma ~5x más rápida que la referencia, pasa KATs de NIST, C2SP/CCTV y pq-crystals), pero **solo KEM**: obligaría a mezclar autores/estilos para ML-DSA y SLH-DSA.
- Candidata como backend alternativo de ML-KEM si los benchmarks lo justifican.

### Alternativas WASM (@oqs/liboqs-js)

- Es el sucesor oficial: openforge-sh/liboqs-node fue archivado en feb 2026 y adoptado por Open Quantum Safe como `@oqs/liboqs-js`. WASM por algoritmo (80–500 KB cada uno), requiere Node 22+ por SIMD.
- Pros: hereda la madurez de liboqs (v0.15, activo). Contras: bundle 5–30x mayor, sin React Native, adopción mínima (~650 descargas/semana), y OQS advierte que liboqs es para experimentación.
- Reevaluar si aparece auditoría formal o si se necesita rendimiento nativo en server.

### liboqs-node (TapuCosmo y forks)

- El original está muerto (v0.1.0, 2022, algoritmos pre-estándar). El fork @skairipaapps tuvo actividad hasta jun 2025. Addon nativo: incompatible con Workers/RN/Deno. **Descartada.**

## Decisión

`@noble/post-quantum` como dependencia base de `@pqc-sdk/core`:

1. Único paquete mantenido que cubre FIPS 203 + 204 + 205 finales.
2. Único compatible con los 4 targets del proyecto (Node, Workers, RN, Deno).
3. Bundle ~16 KB vs 80–500 KB por algoritmo en WASM.
4. Mantenimiento muy activo (release abr 2026) y adopción dominante (~122k/sem).
5. Cumple la regla "nunca implementar primitivas desde cero" delegando en una implementación con KATs y track record (ecosistema noble).

Fuentes: github.com/paulmillr/noble-post-quantum · github.com/dajiaji/crystals-kyber-js ·
github.com/openforge-sh/liboqs-node (archivado → @oqs/liboqs-js) · github.com/TapuCosmo/liboqs-node ·
openquantumsafe.org/liboqs · registry.npmjs.org / api.npmjs.org (versiones y descargas, 2026-06-11)
