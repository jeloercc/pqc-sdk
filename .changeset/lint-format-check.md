---
'@pqc-sdk/core': patch
---

Fold `prettier --check .` into the `lint` turbo task (as a `//#format:check`
root task dependency), so a single `pnpm lint` — locally and in CI — surfaces
formatting issues alongside eslint/tsc, instead of relying on a separate
`format:check` step that's easy to skip when running the gate by hand. Removes
the now-redundant standalone "Format check" step from `.github/workflows/ci.yml`.
No runtime or public API change.
