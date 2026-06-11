# Ejemplo: Cloudflare Workers

Worker que hace generate → encrypt → decrypt en cada request y responde JSON.
No requiere `nodejs_compat`: el SDK solo usa APIs estándar (WebCrypto RNG,
TextEncoder).

```bash
pnpm install   # desde la raíz del monorepo
pnpm --filter @pqc-sdk/example-cloudflare-workers dev
curl http://localhost:8787
# {"ok":true,"algorithm":"ml-kem-768","ciphertextBytes":...,"roundtrip":"..."}
```
