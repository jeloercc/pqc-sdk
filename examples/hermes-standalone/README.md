# Hermes standalone

Valida `@pqc-sdk/core` sobre el engine [Hermes](https://github.com/facebook/hermes)
(el de React Native) **sin simulador ni app RN**: bundle con esbuild, clases
transpiladas con Babel (en RN eso lo hace Metro), y ejecución con el CLI
standalone de Hermes.

> ⚠️ `shims.js` rellena `crypto.getRandomValues` con `Math.random` **solo para
> validar el engine** — no es entropía criptográfica. En una app RN real ese
> global lo provee [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
> con entropía nativa del SO; ese polyfill usa NativeModules y no puede
> correrse standalone.

## Correr

1. Bajá el CLI de Hermes (binarios oficiales del release
   [v0.13.0](https://github.com/facebook/hermes/releases/tag/v0.13.0), los
   últimos publicados standalone; el binario reporta 0.12.0):

   ```bash
   gh release download v0.13.0 -R facebook/hermes -p "hermes-cli-darwin.tar.gz" -D /tmp/hermes-cli
   tar xzf /tmp/hermes-cli/hermes-cli-darwin.tar.gz -C /tmp/hermes-cli
   ```

2. Desde la raíz del monorepo:

   ```bash
   pnpm build --filter=@pqc-sdk/core
   cd examples/hermes-standalone
   HERMES_BIN=/tmp/hermes-cli/hermes pnpm start
   ```

   Para probar el camino de bytecode precompilado (como despliega RN):

   ```bash
   /tmp/hermes-cli/hermesc -emit-binary -out dist/bundle.hbc dist/bundle.js
   /tmp/hermes-cli/hermes dist/bundle.hbc
   ```

## Resultado y notas

Ver [docs/compatibility.md](../../docs/compatibility.md) para el resultado
documentado (qué trae y qué no trae Hermes 0.12, tiempos medidos, y qué falta
para marcar React Native como validado).
