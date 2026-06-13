# Example: Deno

Generate → encrypt → decrypt roundtrip on Deno 2+.

While `@pqc-sdk/core` is not published to npm, the import map in `deno.json`
points to the local build (`packages/core/dist`) and resolves the `@noble/*`
dependencies via `npm:`. Once published,
`"@pqc-sdk/core": "npm:@pqc-sdk/core@^0.0.1"` will be enough.

```bash
pnpm build      # from the root: generates packages/core/dist
cd examples/deno
deno task start
```
