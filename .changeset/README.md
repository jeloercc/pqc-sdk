# Changesets

Cada PR que cambie `@pqc-sdk/core` o `@pqc-sdk/cli` debe incluir un changeset:

```bash
pnpm changeset
```

Al mergear a `main`, el workflow de release abre/actualiza un PR "Version
Packages" con los bumps y changelogs. Mergear ese PR publica a npm con
provenance.
