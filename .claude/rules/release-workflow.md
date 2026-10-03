# Release workflow (changesets)

## Flow

- Every PR touching `packages/*` must include a changeset: run
  `pnpm changeset`, pick the bump, commit the generated `.changeset/*.md`.
  Note `@pqc-sdk/core` and `@pqc-sdk/cli` are `linked` in
  `.changeset/config.json`, so they version together.
- On every push to `main`, `.github/workflows/release.yml`
  (`changesets/action`) either updates the "chore: version packages" PR
  (while changesets are pending) or publishes to npm (when that version PR
  itself is merged).

## The version-PR `action_required` pattern — NOT a failure

- Workflow runs for the `changeset-release/main` branch can end as
  `action_required`. That is GitHub's loop prevention for pushes made with
  `GITHUB_TOKEN`; it is expected, not red. Do not rerun it, "fix" it, or
  report it as a failure.
- The publish that matters is the run for the merge commit on `main`.

## Publishing & verification

- Publish is `pnpm release`: build `packages/*` →
  `pnpm publish -r --no-git-checks` → `changeset tag`.
- Authentication is npm **trusted publishing (OIDC)**: each of the 4
  packages trusts `jeloercc/pqc-sdk`, workflow `release.yml`, no
  environment. The job needs `id-token: write` and npm >= 11.5.1 on PATH
  (`pnpm publish` shells out to `npm`), which `release.yml` installs on
  Node 24. Provenance stays on via `NPM_CONFIG_PROVENANCE=true`.
- There is no npm token. Do not add `NODE_AUTH_TOKEN`/`NPM_TOKEN` back to
  the workflow; if publishing fails with an auth error, check the Trusted
  Publisher settings on npmjs.com (repo, workflow filename) and the npm
  version logged by the release job.
- After every release, verify it actually landed:
  `npm view @pqc-sdk/core version` and `npm view @pqc-sdk/cli version`
  must match the merged version PR.
