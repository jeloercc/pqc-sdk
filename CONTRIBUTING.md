# Contributing

## Development process

Changes to cryptographic behavior require focused review and evidence:

- **Findings before fixes.** Audits and security reviews produce a findings
  report first, with nothing changed in the same pass; remediation lands
  afterwards as separate, reviewable PRs referencing the finding IDs.
- **Tests must fail when the property breaks.** A test guarding a
  cryptographic property tampers every region independently and asserts the
  documented error code — never a raw upstream error leaking through.
- **Claims require execution.** A runtime is only marked supported after the
  real roundtrip ran on that actual runtime. Harness builds and clean bundles
  are explicitly not enough.
- **Serialization changes trip a tripwire.** Golden vectors may only be
  regenerated alongside a spec update and an acknowledged breaking change.
  The suite failing is the intended behaviour, never something to "fix".
- **No primitives written here.** They come from `@noble/*`, always.

The verification evidence for the current implementation is summarised in
[How this is verified](./README.md#how-this-is-verified).

None of this substitutes for an independent third-party audit, which this
project has not had and does not claim.

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
