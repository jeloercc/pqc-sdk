# Ejemplo: Deno

Roundtrip generate → encrypt → decrypt en Deno 2+.

Mientras `@pqc-sdk/core` no esté publicado en npm, el import map de
`deno.json` apunta al build local (`packages/core/dist`) y resuelve las
dependencias `@noble/*` vía `npm:`. Una vez publicado bastará con
`"@pqc-sdk/core": "npm:@pqc-sdk/core@^0.0.1"`.

```bash
pnpm build      # desde la raíz: genera packages/core/dist
cd examples/deno
deno task start
```
