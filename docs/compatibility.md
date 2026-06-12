# Compatibilidad por runtime

Resultados de los ejemplos de `examples/` (roundtrip generate → encrypt →
decrypt con ML-KEM-768 + AES-256-GCM), verificados el 2026-06-11 (Hermes:
2026-06-12).

| Runtime               | Versión probada            | Resultado          | Flags/config necesarios                                                             |
| --------------------- | -------------------------- | ------------------ | ----------------------------------------------------------------------------------- |
| Node                  | 24.11 (target ≥20)         | ✅                 | Ninguno                                                                             |
| Deno                  | 2.8.2                      | ✅                 | Import map mientras no esté publicado; `--allow-read`                               |
| Cloudflare Workers    | wrangler 4 / workerd local | ✅                 | Ninguno — no requiere `nodejs_compat`                                               |
| Hermes (engine de RN) | CLI standalone 0.12        | ✅ engine validado | Polyfill de `crypto.getRandomValues`; transpilar `class` (Metro lo hace en RN)      |
| React Native          | —                          | Engine ✅ / app ⏳ | Falta validar en app real con `react-native-get-random-values` (ver sección Hermes) |

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

## Hermes standalone (`examples/hermes-standalone`)

Validado el 2026-06-12 con el CLI standalone de Hermes (binarios del release
[v0.13.0](https://github.com/facebook/hermes/releases/tag/v0.13.0), ago 2024,
el binario reporta 0.12.0 — son los últimos publicados standalone; el Hermes
embebido en React Native actual es más nuevo). Roundtrip completo OK, tanto
interpretando el JS como ejecutando bytecode precompilado con `hermesc`
(el formato que despliega RN).

**Qué trae Hermes 0.12 de lo que el SDK necesita:**

- ✅ `TextEncoder`, `BigInt`, `async/await`, generators, `??`/`?.`
- ❌ `crypto.getRandomValues` — en RN lo provee `react-native-get-random-values`
  (importarlo **antes** que el SDK); en el ejemplo standalone se shimea solo
  para validar el engine (el polyfill real usa NativeModules y no corre sin RN).
- ❌ Sintaxis `class` — no es problema en RN (Metro/Babel la transpila siempre);
  standalone se transpiló con `@babel/plugin-transform-classes`.
- ❌ `TextDecoder` — el SDK no lo usa internamente (`decrypt` devuelve
  `Uint8Array`), pero si tu app decodifica a string necesita un polyfill
  (p. ej. `text-encoding-polyfill` o `fast-text-encoding`).

**Tiempos medidos** (bytecode, x86_64, interpretado — Hermes no tiene JIT):
keygen 34 ms, encrypt 35 ms, decrypt 43 ms, sign+verify ML-DSA-65 449 ms.
Más lento que V8 pero usable; las firmas ML-DSA conviene no hacerlas en el
hilo de UI.

**Qué falta para marcar React Native como ✅:** correr el roundtrip en una app
RN real (device o simulador) con `react-native-get-random-values` como fuente
de entropía — el shim standalone solo replica su superficie, no valida el
native module ni la integración con Metro.

## Limitaciones generales (heredadas de @noble/post-quantum)

- Sin garantías constant-time (JS con JIT); documentado en la investigación.
- React Native: engine Hermes validado standalone (ver arriba); pendiente la
  validación en app real. Hermes no trae `crypto.getRandomValues`: importar
  `react-native-get-random-values` antes que el SDK.
