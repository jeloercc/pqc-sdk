# Compatibilidad por runtime

Resultados de los ejemplos de `examples/` (roundtrip generate → encrypt →
decrypt con ML-KEM-768 + AES-256-GCM), verificados el 2026-06-11.

| Runtime            | Versión probada            | Resultado      | Flags/config necesarios                                                            |
| ------------------ | -------------------------- | -------------- | ---------------------------------------------------------------------------------- |
| Node               | 24.11 (target ≥20)         | ✅             | Ninguno                                                                            |
| Deno               | 2.8.2                      | ✅             | Import map mientras no esté publicado; `--allow-read`                              |
| Cloudflare Workers | wrangler 4 / workerd local | ✅             | Ninguno — no requiere `nodejs_compat`                                              |
| React Native       | —                          | No probado aún | Requiere polyfill `react-native-get-random-values` (ver docs/research-pqc-libs.md) |

## Node (`examples/node`)

Sin limitaciones. ESM directo, sin flags. El build CJS también funciona
(`require('@pqc-sdk/core')`), verificado en los smoke tests del paso anterior.

## Deno (`examples/deno`)

Funciona, con dos particularidades **temporales** (desaparecen al publicar en npm):

1. Como `@pqc-sdk/core` no está publicado, el import map de `deno.json` apunta
   al build local y debe mapear también los bare specifiers `@noble/*` que el
   bundle ESM deja como externals (Deno los resuelve vía `npm:`). Publicado el
   paquete, basta `"@pqc-sdk/core": "npm:@pqc-sdk/core"`.
2. `--allow-read` para leer el dist local. Con el paquete desde npm no hace falta.

No se necesitó `node_modules` ni `nodeModulesDir`: la resolución `npm:` de Deno
maneja las dependencias transitivas (@noble/hashes) sola.

## Cloudflare Workers (`examples/cloudflare-workers`)

- **No requiere `nodejs_compat`**: el SDK solo usa APIs estándar
  (`crypto.getRandomValues`, `TextEncoder`/`TextDecoder`, `Uint8Array`).
  Verificado con `compatibility_date = 2025-01-01` en workerd local.
- **Bundle**: 78 KiB / 20 KiB gzip de upload total (SDK + @noble/\*), medido con
  `wrangler deploy --dry-run`. Muy por debajo del límite de 1 MiB del plan free.
- **CPU**: el request completo (keygen + encapsulate + AES + decapsulate) tardó
  ~51 ms wall-clock en dev local. El plan free de Workers limita a 10 ms de CPU
  por request: hacer **keygen + encrypt + decrypt en un mismo request** puede
  excederlo. En uso real (una sola operación por request, keys persistidas) cada
  operación individual queda dentro del presupuesto, pero conviene medir con
  `wrangler dev --remote` antes de producción en plan free. En planes pagos
  (límite 30 s) no hay problema.

## Limitaciones generales (heredadas de @noble/post-quantum)

- Sin garantías constant-time (JS con JIT); documentado en la investigación.
- React Native: pendiente de ejemplo. Hermes no trae `crypto.getRandomValues`;
  importar `react-native-get-random-values` antes que el SDK.
