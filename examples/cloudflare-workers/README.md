# Example: Cloudflare Workers

Worker that runs generate → encrypt → decrypt on every request and responds
with JSON. Does not require `nodejs_compat`: the SDK only uses standard APIs
(WebCrypto RNG, TextEncoder).

```bash
pnpm install   # from the monorepo root
pnpm --filter @pqc-sdk/example-cloudflare-workers dev
curl http://localhost:8787
# {"ok":true,"algorithm":"ml-kem-768","ciphertextBytes":...,"roundtrip":"..."}
```
