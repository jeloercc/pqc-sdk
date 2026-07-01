---
'@pqc-sdk/core': patch
---

Add `examples/react-native-expo`, a real Expo (TypeScript) app that validates
`@pqc-sdk/core` with the genuine `react-native-get-random-values` entropy
polyfill (native OS randomness), not the `Math.random` shim used for the
Day-0 standalone Hermes engine test. The app type-checks and bundles cleanly
through Metro (595 modules, Hermes bytecode output) with no simulator/emulator
available in this environment to run it on-device; `docs/compatibility.md` is
updated to "harness ready, on-device run pending" rather than a false ✅, with
the concrete findings (Metro bundle succeeds; standalone Hermes execution of
the real RN bundle fails on bytecode-version mismatch and on private
class-field syntax in the `react-native` package itself).

Also pins `typescript` as an explicit devDependency in `@pqc-sdk/core` and
`@pqc-sdk/cli` (previously relied on hoisting from the workspace root).
Adding the Expo example introduced a second `typescript` version into the
workspace, which made `tsup`'s peer resolution for its DTS build
nondeterministic and broke `@pqc-sdk/core`'s build; pinning the version
locally removes the ambiguity regardless of what other workspace packages
require. No runtime or public API change.
