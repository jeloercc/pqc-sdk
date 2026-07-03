# Development workflow

## Scope

- This session's scope is the pqc-sdk repo only. Never read or write paths
  outside the repository root (e.g. sibling project directories) unless
  explicitly instructed with the full path and a reason.

## Branching

- One branch per work unit, always cut from a freshly updated `main`
  (`git checkout main && git pull` first). Never stack unrelated work on
  an old branch.
- Never commit directly to `main`; everything lands via PR.

## Quality gate

- The gate is: `pnpm turbo run lint test build --force`
  - `lint` already includes Prettier via the `//#format:check` turbo task
    (folded in PR #21) — do not run `format:check` as a separate gate step.
  - `--force` bypasses the turbo cache so results are freshly computed,
    not replayed from a previous run.
- Run the gate locally before pushing and before claiming any work is done.

## CI discipline

- No merge without green PR CI. "Green locally" is not a substitute.
- When CI fails, diagnose the logs first (`gh run view <run-id> --log-failed`)
  and identify the actual error before any rerun. Rerunning without a
  diagnosis hides flakes and wastes signal.
- Known non-failure: the release workflow ending in `action_required` on
  `changeset-release/main` is loop prevention, not a broken build — see
  `release-workflow.md` before touching it.
