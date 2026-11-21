# TypeDoc glob traversal compatibility

`typedoc@0.28.20.patch` lets the pinned documentation generator use minimatch
11.0.9, which fixes [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249).
TypeDoc currently declares minimatch 10.x and calls `Minimatch.matchOne`, which
minimatch 11 no longer exposes. An override alone breaks entry point discovery.

The patch changes only directory traversal to use the public partial-match API.
A separate matcher with `flipNegate` preserves traversal independently of final
file negation; the original matcher still controls which files are included.
No upstream copyright or license files are changed.

The exact TypeDoc version, scoped minimatch override and `patchedDependencies`
entry in `pnpm-workspace.yaml` belong together. pnpm verifies the patch hash
through the lockfile; patch failures must remain installation failures.

`pnpm --filter @pqc-sdk/docs test` covers recursive and exact entry points,
brace expansion, excluded paths, hidden directories and dependency directories.
Run it with the docs build on supported Node runtimes when changing this patch.

Remove the patch, its registration and the scoped override together when an
upstream TypeDoc version supports a patched minimatch. Then refresh the TypeDoc
pin and lockfile and repeat the discovery tests and full documentation build.
