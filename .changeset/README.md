# Changesets

Every PR that changes `@pqc-sdk/core` or `@pqc-sdk/cli` must include a changeset:

```bash
pnpm changeset
```

On merge to `main`, the release workflow opens/updates a "Version Packages"
PR with the bumps and changelogs. Merging that PR publishes to npm with
provenance.
