# Contributing

## Development process

**This project is developed with AI assistance.** Every commit carries a
`Co-Authored-By` trailer saying so, and the working agreements the assistant
operates under are checked into the repo rather than kept out of sight:
[`CLAUDE.md`](./CLAUDE.md) and [`.claude/rules/`](./.claude/rules/).

That is stated up front because it is the honest framing of a fair question:
AI-assisted cryptographic code deserves more scrutiny, not less. The answer
this repo offers is not that the tooling is unremarkable — it is the
verification regime the tooling is held to, which exists precisely because of
how the code is written:

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

The standing discipline is [`.claude/rules/crypto-review.md`](./.claude/rules/crypto-review.md);
read it before contributing anything that touches crypto. What that discipline
has actually caught — and what evidence backs each layer — is summarised in
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
