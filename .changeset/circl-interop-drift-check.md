---
'@pqc-sdk/core': patch
---

Added a monthly (`workflow_dispatch`-able) scheduled check for drift on the CIRCL interop vectors added in the previous patch: `.github/workflows/circl-interop-drift-check.yml` and `packages/core/scripts/check-circl-drift.mjs`, mirroring the existing `@noble/post-quantum` vendor-drift check (`vendor-drift-check.yml` / `check-vendor-drift.mjs`).

Detects whether a newer `github.com/cloudflare/circl` release is published than the version recorded in the three interop vector files' own `meta.counterpartVersion`. Detect-and-notify only: opens or updates a single tracking issue naming the recorded/latest versions, the affected vector files, and the exact `regenerateCommand` already stored in their `meta` — it never regenerates the vectors and never opens a PR. Regenerating still requires Go, the CIRCL helper, and a human reading the cross-check results; the issue body states plainly that a mismatch found after regenerating is a finding to investigate, not a test to fix.

No Go in CI: the check reads the Go module proxy over plain HTTPS (`https://proxy.golang.org/github.com/cloudflare/circl/@latest`), never the `go` binary.

Includes test coverage (`packages/core/scripts/__tests__/check-circl-drift.test.mjs`, 5 cases, no network calls — the version lookup is stubbed) for the same reason PR #81 added it for the vendor check: an untested scheduled script fails silently, and nobody notices until the day it mattered.

CI config + test only — no `packages/*` runtime behavior changed.
