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
don't need one. On merge to `main`, Changesets proposes a version PR. Reproduce
an accepted version update on an owner-authored branch with `pnpm version-packages`
and review its generated manifests and changelogs before integrating it.

## Attribution and reviewed merges

`scripts/contributor-policy.json` records the owner's public account ID, accepted
Git identities and a reviewed history baseline. Keep credentials out of this file.
The attribution guard checks the PR creator, every introduced commit and additional
author-credit trailers. Automated proposals remain available for review, but their
bot-authored commits are not integrated directly into main.

For an accepted automated update, reproduce the reviewed change on a new branch
from main with the owner's identity, open a new PR and link the original proposal.
Do not change human authorship or remove third-party license notices. A human
contribution from another author needs an explicit policy decision before merging.

The merge helper defaults to inspection only:

```sh
node scripts/merge-reviewed-pr.mjs --pr PR_NUMBER --head REVIEWED_HEAD_SHA
```

After explicit authorization, `--apply` requests an exact-head squash. It requires
all reported checks, the trusted `policy/owner-attribution` status and its completed
default-branch workflow. It verifies the resulting author, parent and tree; it
never bypasses rules, rewrites history or repairs an unexpected merge automatically.
If the API fails during a merge, inspect the PR before attempting recovery. A closed
PR is rejected rather than merged again. The helper uses the existing `gh` session;
it does not extract tokens or create credentials.

The trusted PR workflow reads metadata without checking out the PR head or
installing dependencies. Its only write permission is for commit statuses.
The Release validation job reads the actual main history before the separate job
with publishing/OIDC permissions can start. GitHub's platform committer is not
treated as an additional author; the actual commit author still must be permitted.

The first PR installing these controls needs manual owner-attribution review with
the existing required CI. After the workflow is on main, verify its status on the
PR head and its source before separately authorizing the new required context.
Do not enable a missing check or weaken the existing Node 20/24 requirements.
Review the applicable Actions event policies before activation. If an event policy
blocks this workflow, stop and revise the integration plan; do not automatically
add a policy exception or require a status that cannot run.
Contributors is cached and is not used as the execution gate. These controls do not
prevent an administrator from deliberately editing repository policy or rules.

## Security reports

Do not open public issues for vulnerabilities: see [SECURITY.md](./SECURITY.md).

<!-- Temporary owner attribution reject validation; this branch is not intended for merge. -->
