# OpenSSF Scorecard review — @pqc-sdk (November 2026)

> **Scope & stance.** This report reviews the OpenSSF Scorecard result for
> `jeloercc/pqc-sdk` at `main` @ `621f17b` (Scorecard v5.6.0, run of
> 2026-10-31, overall score **5.8 / 10**) as part of the preparation for the
> independent audit ([#112](https://github.com/jeloercc/pqc-sdk/pull/112)).
> Each failing check was traced to its cause in the repository, its CI, or the
> repository settings, and one documentation error found along the way is
> included. It is a findings report only — **nothing was changed** in the pass
> that produced it. Remediation lands in separate PRs that reference the IDs
> below. Like the earlier reports, it is an internal, AI-assisted review, not an
> independent third-party audit.
>
> **Method / evidence collected this run (2026-11-02):**
>
> - Scorecard result JSON from the log of the Scorecard workflow run
>   [41179874952](https://github.com/jeloercc/pqc-sdk/actions/runs/41179874952)
>   (`main` @ `621f17b`), where the action prints the full result. The SARIF
>   artifact and the public Scorecard API were not reachable from the review
>   environment.
> - Scorecard source at the commit that produced the result (`61e8474`), read
>   for the scoring rules cited below (`checks/raw/`, `checks/evaluation/`,
>   `probes/`).
> - GitHub REST API: `rules/branches/main`, `rulesets/25837073`,
>   `branches/main`, repository collaborators, check runs and commit statuses
>   for the head commits of the 30 most recently merged PRs (#93–#123), and CI
>   runs on `changeset-release/main`.
> - `npm view` for the dependencies of `vitest` and `@vitest/coverage-v8`
>   4.1.12.
> - `pnpm audit --json` and `pnpm list -r vitest` on `621f17b`.
> - The CycloneDX SBOMs attached to the five most recent GitHub releases,
>   downloaded and compared against the advisories.
> - `https://nodejs.org/dist/index.json` for the npm version bundled with each
>   Node 24 release.
> - The code-scanning alerts API was not accessible to the review environment
>   (`Resource not accessible by integration`). The alert numbers below are
>   those shown on the repository's Code scanning page on 2026-11-02.

## Headline

No finding affects the published packages or the cryptographic code. None of
the six advisories behind the Vulnerabilities check is in the runtime
dependency tree of the five most recent releases, per their attached SBOMs.
The two Medium findings concern what an auditor reads and what the release
job runs: **the threat model and audit
scope state that `main` has no branch protection, but a ruleset has enforced
pull requests and CI on `main` since 2026-10-25** (SC-M1), and **the release
job installs npm from a floating range** in the job that holds the OIDC
publishing permission (SC-M2). The remaining items are CI coverage (no SAST
tool Scorecard recognizes, no dependency update tool), development-only
advisories whose fixes need major upgrades, and governance properties that
follow from the project having one collaborator.

## Findings by severity

Severities are this review's, on the scale used by `docs/AUDIT-2026-06.md` and
`docs/AUDIT-2026-09.md`. The GitHub label of each Scorecard alert reflects
Scorecard's per-check risk and is listed separately in the next table.

| ID    | Sev    | Area                 | Summary                                                                                      | Status   |
| ----- | ------ | -------------------- | -------------------------------------------------------------------------------------------- | -------- |
| SC-M1 | Medium | Docs/audit           | THREAT-MODEL and AUDIT-SCOPE say `main` has no branch protection; a ruleset enforces PR + CI | Resolved |
| SC-M2 | Medium | Supply chain/release | `release.yml` installs `npm@^11.5.1` in the job that holds `id-token: write`                 | Resolved |
| SC-L1 | Low    | Dev tooling          | Six advisories in development dependencies; every fix needs a major upgrade                  | Resolved |
| SC-L2 | Low    | CI                   | No SAST tool that Scorecard recognizes runs on commits                                       | Resolved |
| SC-L3 | Low    | Supply chain         | No automated dependency update tool is configured                                            | Resolved |
| SC-L4 | Low    | Governance           | Changes reach `main` without review by a second person                                       | Open     |
| SC-I1 | Info   | Release integrity    | GitHub release assets (the SBOMs) are not signed                                             | Open     |
| SC-I2 | Info   | CI                   | Five version PRs were merged with no CI check run on their head commit                       | Open     |
| SC-I3 | Info   | Governance           | No OpenSSF Best Practices badge                                                              | Open     |
| SC-I4 | Info   | Governance           | Scorecard finds contributors from no organization                                            | Open     |

### Scorecard checks below 10 and their findings

| Scorecard check        | Score | GitHub alert | GitHub label | Finding      |
| ---------------------- | ----- | ------------ | ------------ | ------------ |
| Code-Review            | 0     | #9           | High         | SC-L4        |
| Vulnerabilities        | 4     | #8           | High         | SC-L1        |
| Dependency-Update-Tool | 0     | #6           | High         | SC-L3        |
| Branch-Protection      | 4     | #1           | High         | SC-L4, SC-M1 |
| SAST                   | 0     | #7           | Medium       | SC-L2        |
| Pinned-Dependencies    | 9     | #5           | Medium       | SC-M2        |
| CI-Tests               | 8     | #11          | Low          | SC-I2        |
| CII-Best-Practices     | 0     | #10          | Low          | SC-I3        |
| Signed-Releases        | 0     | —            | —            | SC-I1        |
| Contributors           | 0     | —            | —            | SC-I4        |
| Packaging              | −1    | —            | —            | (none)       |

Signed-Releases and Contributors had no open alert on 2026-11-02. Packaging is
inconclusive ("no GitHub/GitLab publishing workflow detected") although
`release.yml` publishes to npm through `changesets/action` → `pnpm release`;
the check does not recognize that path. It is not a finding.

---

## Medium

### [Medium][Docs/audit] SC-M1 — Audit documents state that `main` has no branch protection

**Where:** `docs/security/THREAT-MODEL.md:224-229` (§3.4, "Repository and
account compromise"), `docs/security/AUDIT-SCOPE.md:178-179` (§5, item 5).

> "`main` currently has **no branch protection and no rulesets**, and the
> project has a single maintainer. Anyone with write access to the repository
> (or the maintainer's GitHub account) can push to `main`, which runs
> `release.yml` with `id-token: write` and can publish with provenance."

> "**`main` has no branch protection or rulesets** (checked 2026-10-25)"

`GET /repos/jeloercc/pqc-sdk/rules/branches/main` returns the rules of
repository ruleset `25837073` (`protect-main`, `enforcement: active`,
`bypass_actors: []`):

- `deletion` and `non_fast_forward`: `main` cannot be deleted or force-pushed;
- `pull_request`: changes land only through a pull request,
  `required_approving_review_count: 0`, merge method `squash` only;
- `required_status_checks` (strict): `ci (node 20)` and `ci (node 24)` must
  pass on an up-to-date branch.

`GET /repos/jeloercc/pqc-sdk/rulesets/25837073` reports `created_at`
2026-10-25T16:01:17-05:00 (21:01 UTC) and `updated_at`
2026-10-27T14:47:59-05:00. Both statements were introduced by #112, whose
merge commit `7a8e614` started release run 124 at 2026-10-25T21:37:40Z, about
36 minutes after the ruleset was created. Scorecard's Branch-Protection
details agree with the API ("PRs are required in order to make changes on
branch 'main'", "'force pushes' disabled", "status check found to merge onto
on branch 'main'").

The documents prepared for the auditor therefore understate the controls on
`main`. The threat in §3.4 is still real in a narrower form: there is one
collaborator (`jeloercc`, admin) and no required approval (SC-L4), so a
compromised maintainer account can still merge a change that passes CI, and
repository admins can edit or disable rulesets. What no longer holds is
"can push to `main`": a direct push is rejected for every actor, because the
ruleset has no bypass actors.

**Suggested fix:** Rewrite THREAT-MODEL §3.4 and AUDIT-SCOPE §5 item 5 to
describe ruleset `protect-main` as it is, with the API call that verifies it,
and keep the residual risk (no second reviewer, admin can change the ruleset).
Link this report from AUDIT-SCOPE §4 in the same PR.

### [Medium][Supply chain/release] SC-M2 — The release job installs npm from a floating range

**Where:** `.github/workflows/release.yml:34-37`, inside the `release` job,
whose permissions are `contents: write`, `pull-requests: write` and
`id-token: write` (`release.yml:15-18`).

```yaml
- name: Upgrade npm for trusted publishing
  run: |
    npm install -g npm@^11.5.1
    npm --version
```

Scorecard (Pinned-Dependencies, 9): "Warn: npmCommand not pinned by hash:
.github/workflows/release.yml:36". It is the only item the check flags; all
20 GitHub-owned and 7 third-party action references are pinned by commit SHA.

Each release therefore runs whatever npm release satisfies `^11.5.1` at that
moment, unreviewed, in the job that can publish all four packages through
OIDC. In release run
[40237918263](https://github.com/jeloercc/pqc-sdk/actions/runs/40237918263)
that was npm 11.21.1 (the `npm --version` output of the "Upgrade npm for
trusted publishing" step).

Two facts constrain the fix:

- **Pinning an exact version does not clear the check.** Scorecard treats
  every `npm install` as unpinned unless the command is `npm ci` or installs a
  git URL with a commit hash (`checks/raw/shell_download_validate.go:464-490`
  at `61e8474`).
- **The step is not needed for the npm version requirement.** Trusted
  publishing needs npm ≥ 11.5.1 (`.claude/rules/release-workflow.md:28`).
  Node 24.5.0 and later bundle npm ≥ 11.5.1, according to
  `nodejs.org/dist/index.json` (v24.5.0 → npm 11.5.1). The runner's Node
  24.21.0 (same run) bundles npm 11.19.0.

The Node runtime itself is resolved at run time as the latest 24.x
(`release.yml:28`, `node-version: 24`); Scorecard does not flag that.

**Suggested fix:** Remove the `npm install -g` step and replace it with a step
that only checks the bundled npm and fails the job if it is below 11.5.1.
Update `.claude/rules/release-workflow.md` and the release-flow notes in
`CLAUDE.md` to match. The change can only be confirmed on the next real
release: check the npm version line in the job log, and `npm view
<pkg>@<version> dist.attestations` for provenance.

---

## Low

### [Low][Dev tooling] SC-L1 — Six advisories in development dependencies

**Where:** `pnpm-lock.yaml`. `vitest` 3.2.6 is the single vitest version used
by all five workspaces with tests (`packages/core`, `packages/cli`,
`packages/langchain`, `packages/mcp-server`, `evals/open-models`; from
`pnpm list -r vitest`).

| Advisory                                                                 | Package          | Installed            | GitHub severity | Fixed in | Reached through (examples from `pnpm audit`)                 |
| ------------------------------------------------------------------------ | ---------------- | -------------------- | --------------- | -------- | ------------------------------------------------------------ |
| [GHSA-5gmw-xhrv-c9v3](https://osv.dev/vulnerability/GHSA-5gmw-xhrv-c9v3) | `tinypool`       | 1.1.1                | Critical        | ≥ 2.1.1  | `vitest` 3.2.6                                               |
| [GHSA-85c8-ppgw-ccpr](https://osv.dev/vulnerability/GHSA-85c8-ppgw-ccpr) | `tinypool`       | 1.1.1                | Critical        | ≥ 2.1.2  | `vitest` 3.2.6                                               |
| [GHSA-82fw-gwwq-j7x9](https://osv.dev/vulnerability/GHSA-82fw-gwwq-j7x9) | `vitest`         | 3.2.6                | Moderate        | ≥ 4.1.11 | direct dev dependency                                        |
| [GHSA-qxg6-89mg-rqv8](https://osv.dev/vulnerability/GHSA-qxg6-89mg-rqv8) | `@vitest/mocker` | 3.2.6                | Moderate        | ≥ 4.1.12 | `vitest` 3.2.6                                               |
| [GHSA-3g3m-2fjr-6pw4](https://osv.dev/vulnerability/GHSA-3g3m-2fjr-6pw4) | `glob`           | 10.5.0, 13.0.6       | Moderate        | ≥ 14.0.2 | `@vitest/coverage-v8` → `test-exclude`; `expo` → `@expo/cli` |
| [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) | `minimatch`      | 3.1.5, 9.0.9, 10.2.5 | Moderate        | ≥ 11.0.1 | `eslint`; `typescript-eslint`; `expo` → `@expo/cli`          |

These are exactly the six advisories Scorecard reports (Vulnerabilities, 4).
None of them is listed in `osv-scanner.toml`, which holds the reviewed
exceptions from #123.

**Not shipped:** none of the six packages appears, at an affected version, in
the SBOMs attached to the releases of `@pqc-sdk/core` 0.11.3,
`@pqc-sdk/cli` 0.11.3, `@pqc-sdk/langchain` 0.3.3 and `@pqc-sdk/mcp-server`
0.4.2 and 0.4.3. They run only in local development and CI. Exploitability in
this repository's CI was not analyzed advisory by advisory; severity here
rests on the absence of consumer exposure.

Every fix is a major upgrade. In the lockfile, `tinypool` is reached only
through `vitest@3.2.6`, and `vitest@4.1.12` no longer depends on `tinypool`
(`npm view`). So moving to `vitest` ≥ 4.1.12 is expected to clear the four
`vitest`, `@vitest/mocker` and `tinypool` advisories; `pnpm audit` after the
migration has to confirm it. The current `vitest` release is 5.0.5, so the
target major is part of the decision. `glob` and `minimatch` are transitive:
`@vitest/coverage-v8@4.1.12` no longer depends on `test-exclude`, but
`test-exclude` is also reached through `babel-plugin-istanbul`. Together with
`eslint`, `typescript-eslint` and `expo`, these depend on upstream releases.

**Suggested fix (decision D1):** either (A) migrate the five workspaces to
vitest ≥ 4.1.12, re-checking the vitest configs and the 90% coverage floor; or
(B) record each advisory in `osv-scanner.toml` with a reason, as #123 did. The
two options can be combined: A for the vitest family, B for `glob` and
`minimatch` until upstream releases exist.

### [Low][CI] SC-L2 — No SAST tool that Scorecard recognizes

**Where:** `.github/workflows/` (no CodeQL or Sonar workflow; the only use of
`github/codeql-action` is `upload-sarif` in `scorecard.yml:56`, which uploads
the Scorecard SARIF).

Scorecard (SAST, 0): "0 commits out of 30 are checked with a SAST tool". The
check counts check runs from the apps `github-advanced-security`,
`github-code-scanning`, `lgtm-com`, `sonarcloud` and `sonarqubecloud`. It also
counts workflows that use `github/codeql-action/analyze`, Sonar or
`snyk/actions/*` (`checks/raw/sast.go:39-45,59-75` at `61e8474`).

A Snyk integration posts `security/snyk (jeloercc)` commit statuses (for
example on #108, head `0ad16ce`: "9 security tests have passed"; on #99: "No
manifest changes detected in 9 projects"). The wording points to dependency
manifest scanning rather than code analysis. Its configuration lives outside
the repository and was not inspected. Scorecard does not count it.

**Suggested fix:** Add a CodeQL workflow (`javascript-typescript`) on
`pull_request` and `push` to `main`, with actions pinned by commit SHA and
`security-events: write` only on the analysis job. Whether it becomes a
required check in `protect-main` is decision D5.

### [Low][Supply chain] SC-L3 — No automated dependency update tool

**Where:** repository root and `.github/` (no `dependabot.yml`, no Renovate
configuration). These are the files Scorecard looks for
(`checks/raw/dependency_update_tool.go:81-104` at `61e8474`).

Scorecard (Dependency-Update-Tool, 0): "no update tool detected". Updates are
made by hand (for example #122). SECURITY.md ("Dependency policy") pins the
cryptographic dependencies to exact versions on purpose: they are bumped
deliberately, behind the NIST vector tests. An update tool would have to
respect that, by excluding `@noble/*` or by grouping it into PRs that run the
vector suites.

**Suggested fix (decision D2):** Dependabot, Renovate, or no tool with the
reason recorded in SECURITY.md. With a tool, the GitHub Actions ecosystem is
the low-risk starting point: it keeps the SHA pins current.

### [Low][Governance] SC-L4 — Changes reach `main` without a second reviewer

**Where:** ruleset `protect-main` (`required_approving_review_count: 0`, no
code-owner review, no last-push approval); no `CODEOWNERS` file.

- Repository collaborators: one (`jeloercc`, role `admin`).
- Scorecard Code-Review, 0: "Found 0/23 approved changesets". Bot-authored
  changesets are not counted (`probes/codeApproved/impl.go:80-86` at
  `61e8474`), so the 23 are all the human-authored changesets in the window.
- Scorecard Branch-Protection, 4: warnings for no required approvers, no
  code-owner review, stale-review dismissal disabled and last-push approval
  disabled. The last two only take effect when approvals are required.

GitHub does not let the author of a pull request approve it, and the ruleset
has no bypass actors. With one collaborator, requiring an approval would
therefore block every merge. THREAT-MODEL §3.4 already names the single
maintainer as a risk; this finding records the Scorecard consequence.

**Suggested fix (decision D4):** either accept the risk, dismiss alerts #9 and
#1 on GitHub with a reason that points here, and keep the THREAT-MODEL text;
or add a second reviewer and then require one approval, code-owner review and
last-push approval.

---

## Info

### [Info][Release integrity] SC-I1 — GitHub release assets are not signed

Scorecard (Signed-Releases, 0) warns for each of the five most recent releases
that the artifact is "not signed" and "does not have provenance". The check
only considers release assets with the extensions `.asc`, `.minisig`, `.sig`,
`.sign`, `.sigstore` or `.sigstore.json`, or `.intoto.jsonl` for provenance
(`probes/releasesAreSigned/impl.go:43`,
`probes/releasesHaveProvenance/impl.go:43` at `61e8474`).

The npm packages do carry SLSA provenance. On 2026-10-25,
`@pqc-sdk/core@0.11.3`, `cli@0.11.3`, `langchain@0.3.3` and `mcp-server@0.4.2`
were checked: each attestation names `jeloercc/pqc-sdk`, `release.yml` and
commit `a4b84f0`. Scorecard does not look at npm provenance. Each GitHub
release currently has one asset, its CycloneDX SBOM. Anyone with write access
to the repository can replace that asset, and no signature lets a consumer
verify that it came from the release job.

**Suggested fix (decision D3):** optionally sign each SBOM in the release job
(for example a Sigstore bundle, `.sigstore.json`) and attach the signature next
to it. This touches the release pipeline.

### [Info][CI] SC-I2 — Five version PRs merged without a CI check run

Scorecard (CI-Tests, 8): "25 out of 30 merged PRs checked by a CI test". The
five are the changesets version PRs #94, #97, #99, #103 and #108. Their head
commits have no check runs. Their only status is `security/snyk (jeloercc)`,
which does not match the CI names Scorecard accepts
(`probes/testsRunInCI/impl.go:165-167` at `61e8474`).

Among the 20 most recent CI runs on `changeset-release/main`, all 15 first
attempts triggered by `github-actions[bot]` ended as `failure`. The one
inspected, run
[37084447013](https://github.com/jeloercc/pqc-sdk/actions/runs/37084447013)
for #108, has 0 jobs. The two most recent version PRs, #114 and #120, do have
CI: a second run triggered by `jeloercc` passed on each (runs 40237758628 and
40582228273). Both were merged after `protect-main` was created; the ruleset
was last updated on 2026-10-27, and its history API was not accessible to the
review environment, so whether it required CI when #114 was merged
(2026-10-25T21:57:43Z) is not established.

As configured today (`ci (node 20)` and `ci (node 24)` required, no bypass
actors), a version PR cannot merge without CI, so the gap does not recur while
the ruleset stays as it is. The five PRs leave Scorecard's 30-PR window as new
PRs merge. A process note remains: each version PR needs CI triggered by a
person.

**Suggested fix:** none required.

### [Info][Governance] SC-I3 — No OpenSSF Best Practices badge

Scorecard (CII-Best-Practices, 0): "no effort to earn an OpenSSF best practices
badge detected". Earning the badge means registering the project at
`bestpractices.dev` with the maintainer's account and answering its
questionnaire. That is an owner action, not a repository change.

**Suggested fix (decision D6):** owner's choice.

### [Info][Governance] SC-I4 — No contributing organizations

Scorecard (Contributors, 0): "project has 0 contributing companies or
organizations". The check reads the `Company` field of recent commit authors.
In the last 30 commits on `main` there are 23 by `jeloercc` and 7 by
`github-actions[bot]`. This is structural for a single-maintainer project.

**Suggested fix:** none.

---

## Confirmed sound (checked, no finding)

- **Workflow token permissions (Token-Permissions, 10).** Every workflow sets
  a read-only top-level token. The only job-level writes are in
  `release.yml:15-18` (`contents`, `pull-requests`, `id-token`), which
  publishing requires.
- **Action pinning.** All 20 GitHub-owned and 7 third-party action references
  are pinned by commit SHA (Pinned-Dependencies details). The one unpinned
  item is SC-M2.
- **No dangerous workflow patterns (10), no binaries in the repository (10).**
- **Security policy (10) and license (10):** `SECURITY.md` with a disclosure
  process; MIT `LICENSE`.
- **Fuzzing (10):** property-based tests with fast-check in
  `packages/core/src/properties.test.ts` and `deserialize-fuzz.test.ts`.
- **Maintained (10):** 30 commits and 4 issues with activity in the last 90
  days.
- **SBOMs:** each of the five releases listed in SC-L1 has exactly one
  CycloneDX SBOM attached, with the matching package and version as its main
  component. The 0.11.3 / 0.3.3 / 0.4.2 SBOMs were attached after #115; the
  release job attached the 0.4.3 SBOM itself (run 40582796517).

## Suggested remediation order

1. **SC-M1:** correct THREAT-MODEL §3.4 and AUDIT-SCOPE §5; link this report
   from AUDIT-SCOPE §4. Docs only; it fixes what the auditor reads.
2. **SC-L2** (CodeQL, a new workflow) and **SC-M2** (drop the npm install
   step). SC-M2 changes the release job, so it lands as its own PR and is
   confirmed only on the next release.
3. **SC-L1** and **SC-L3**, after decisions D1 (vitest 4 or recorded
   exceptions) and D2 (update tool and `@noble/*` policy).
4. **SC-I1**, if decision D3 is to sign release assets.
5. **SC-L4**, **SC-I3**: owner decisions D4 and D6. **SC-I2** and **SC-I4**
   need no change.

| Decision | Question                                                      | Finding |
| -------- | ------------------------------------------------------------- | ------- |
| D1       | Migrate vitest (to 4.1.12+ or 5.x), or record the advisories? | SC-L1   |
| D2       | Dependabot, Renovate or none; policy for `@noble/*`           | SC-L3   |
| D3       | Sign GitHub release assets?                                   | SC-I1   |
| D4       | Accept single-maintainer review risk, or add a reviewer?      | SC-L4   |
| D5       | Make CodeQL a required check in `protect-main`?               | SC-L2   |
| D6       | Register the project at bestpractices.dev?                    | SC-I3   |

## Resolution log

"Resolved" means merged to `main`. The findings and their evidence above are
left as they were at `621f17b`; this log records what changed afterwards.

| ID    | Status   | Resolved in                                                                                                                                                                                                                                                                                            |
| ----- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| SC-M1 | Resolved | [#125](https://github.com/jeloercc/pqc-sdk/pull/125) — THREAT-MODEL §3.4 describes `protect-main` and keeps the residual risk; AUDIT-SCOPE §5 item 5 corrected, report linked in §4                                                                                                                    |
| SC-L2 | Resolved | [#126](https://github.com/jeloercc/pqc-sdk/pull/126) — `.github/workflows/codeql.yml` (CodeQL `javascript-typescript`, on PRs, pushes to `main` and weekly); not a required check (D5 open)                                                                                                            |
| SC-M2 | Resolved | [#127](https://github.com/jeloercc/pqc-sdk/pull/127) — `npm install -g` step replaced by a check of the bundled npm (fails below 11.5.1); Scorecard v5.6.0 `--local` Pinned-Dependencies 9 → 10; the check passed in Release run 41526886771 (npm 11.19.1); publishing with it awaits the next release |
| SC-L1 | Resolved | [#128](https://github.com/jeloercc/pqc-sdk/pull/128) — vitest 4.1.12 in all five workspaces clears GHSA-5gmw, -85c8, -82fw, -qxg6 (`tinypool` left the lockfile); `glob` 13.0.6 and `minimatch` 3.1.5 / 9.0.9 / 10.2.5 recorded in `osv-scanner.toml` (decision D1)                                    |
| SC-L3 | Resolved | [#129](https://github.com/jeloercc/pqc-sdk/pull/129) — `.github/dependabot.yml`: weekly updates for GitHub Actions and npm; `@noble/*` in its own group, not ignored, so security updates still arrive (decision D2); Scorecard v5.6.0 `--local` Dependency-Update-Tool 0 → 10                         |
| SC-L3 | Resolved | [#136](https://github.com/jeloercc/pqc-sdk/pull/136) — follow-up: the first run put `@noble/ciphers` into the production group (#132), so the other groups now exclude `@noble/*`; Actions majors are no longer grouped; vitest / `@vitest/*` majors are ignored (D1)                                  |
