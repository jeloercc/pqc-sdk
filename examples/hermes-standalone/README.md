# Standalone Hermes

Validates `@pqc-sdk/core` on the [Hermes](https://github.com/facebook/hermes)
engine (React Native's) **without a simulator or RN app**: bundle with esbuild,
classes transpiled with Babel (Metro does that in RN), and execution with the
standalone Hermes CLI.

> ⚠️ `shims.js` fills `crypto.getRandomValues` with `Math.random` **only to
> validate the engine** — it is not cryptographic entropy. In a real RN app
> that global is provided by
> [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
> with native OS entropy; that polyfill uses NativeModules and cannot run
> standalone.

## Run

1. Download the Hermes CLI (official binaries from the
   [v0.13.0](https://github.com/facebook/hermes/releases/tag/v0.13.0) release,
   the latest published standalone; the binary reports 0.12.0):

   ```bash
   gh release download v0.13.0 -R facebook/hermes -p "hermes-cli-darwin.tar.gz" -D /tmp/hermes-cli
   tar xzf /tmp/hermes-cli/hermes-cli-darwin.tar.gz -C /tmp/hermes-cli
   ```

2. From the monorepo root:

   ```bash
   pnpm build --filter=@pqc-sdk/core
   cd examples/hermes-standalone
   HERMES_BIN=/tmp/hermes-cli/hermes pnpm start
   ```

   To test the precompiled bytecode path (how RN ships):

   ```bash
   /tmp/hermes-cli/hermesc -emit-binary -out dist/bundle.hbc dist/bundle.js
   /tmp/hermes-cli/hermes dist/bundle.hbc
   ```

## Result and notes

See [docs/compatibility.md](../../docs/compatibility.md) for the documented
result (what Hermes 0.12 does and does not ship, measured timings, and what is
missing to mark React Native as validated).
