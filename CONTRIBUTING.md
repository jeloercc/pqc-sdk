# Contributing

## Running the repo

Requirements: Node 20+ and pnpm (the exact version is in the `packageManager`
field of `package.json`; `corepack enable` is enough).

```bash
pnpm install
pnpm build          # turbo run build (core → cli → docs)
pnpm test           # Vitest; core runs with --coverage (90% minimum)
pnpm lint           # eslint + tsc --noEmit
pnpm format         # prettier --write
```

To iterate on a single package: `pnpm dev --filter=@pqc-sdk/core` (or `cli`,
or `@pqc-sdk/docs` for the site).

## Project rules

- **We never implement cryptographic primitives.** They come from `@noble/*`;
  a PR implementing a primitive from scratch gets rejected outright.
- Strict TypeScript. Every public function carries JSDoc with a usage example.
- Safe defaults, zero-config API.
- All user-facing text is in English: CLI output, error messages, JSDoc,
  READMEs, docs, changesets, code comments, and commit messages.

## Commits

We use [Conventional Commits](https://www.conventionalcommits.org/):
`fix(core): ...`, `feat(cli): ...`, `docs: ...`, `ci: ...`, etc.

## Changesets

Every PR that changes a publishable package (`packages/*`) needs a changeset:

```bash
pnpm changeset
```

Pick the bump (`patch`/`minor`) and describe the change from the user's
perspective — that text goes into the CHANGELOG. Docs, CI or example changes
don't need one. Releases are automated: on merge to `main`, the changesets bot
opens a version PR and publishes to npm when it gets merged.

## Security reports

Do not open public issues for vulnerabilities: see [SECURITY.md](./SECURITY.md).
