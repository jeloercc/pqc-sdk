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
  `pnpm publish -r --no-git-checks` → `changeset tag`, with npm provenance
  (`NPM_CONFIG_PROVENANCE=true` + OIDC `id-token: write`).
- After every release, verify it actually landed:
  `npm view @pqc-sdk/core version` and `npm view @pqc-sdk/cli version`
  must match the merged version PR.
- The npm token lives only in the `NPM_TOKEN` repo secret. Never echo,
  log, or copy it into files or session output.
