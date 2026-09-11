#!/usr/bin/env node
/**
 * Detect-and-notify check for the vendored @noble/post-quantum copies under
 * packages/core/src/vendor/{ml-kem,ml-dsa}/.
 *
 * Reports two independent signals, on purpose kept separate:
 *
 *   (a) version-drift  — a newer @noble/post-quantum is published on npm than
 *       the version pinned in packages/core/package.json.
 *   (b) baseline-drift — the "sha256 of the pristine copy, before local
 *       edits" digest recorded in NOTICE.md / a vendored file's own header no
 *       longer matches a fresh copy of that same file at the pinned version.
 *       That digest is the documented starting point every listed
 *       modification is diffed against, so a mismatch means the record of
 *       what upstream looked like — not just our copy — needs a human look.
 *
 * This script only reads npm and the repo; it never writes to
 * package.json or to any vendored file. See
 * packages/core/src/vendor/ml-kem/NOTICE.md for the actual re-vendoring
 * procedure, which stays a manual, reviewed process.
 *
 * Writes `has-drift` (and, on drift, `issue-title`) to $GITHUB_OUTPUT when
 * run in Actions, and the issue body to the file path given by --report
 * (default: vendor-drift-report.md in the current directory).
 *
 * Usage: node scripts/check-vendor-drift.mjs [--report <path>]
 *
 * `evaluateDrift` and friends below are exported so __tests__/ can exercise
 * the real logic against fixture directories with the network calls
 * (`fetchLatestVersion`, `fetchPristineSource`) stubbed out — see
 * scripts/__tests__/check-vendor-drift.test.mjs.
 */
import { execFileSync } from 'node:child_process';
import console from 'node:console';
import { createHash } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const PACKAGE = '@noble/post-quantum';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORE_DIR = join(SCRIPT_DIR, '..');
const NOTICE_REL = 'packages/core/src/vendor/ml-kem/NOTICE.md';

/** The four vendored files, and where each one's recorded pristine digest lives. */
export function vendoredFilesFor(coreDir) {
  const kemDir = join(coreDir, 'src/vendor/ml-kem');
  const dsaDir = join(coreDir, 'src/vendor/ml-dsa');
  return [
    { rel: 'ml-kem.ts', dir: kemDir, upstream: 'src/ml-kem.ts', digestSource: 'notice' },
    { rel: '_crystals.ts', dir: kemDir, upstream: 'src/_crystals.ts', digestSource: 'notice' },
    { rel: 'utils.ts', dir: kemDir, upstream: 'src/utils.ts', digestSource: 'notice' },
    { rel: 'ml-dsa.ts', dir: dsaDir, upstream: 'src/ml-dsa.ts', digestSource: 'header' },
  ];
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function recordedDigestFromNotice(noticePath, fileName) {
  const notice = readFileSync(noticePath, 'utf8');
  const rowIdx = notice.indexOf(`\`${fileName}\``);
  if (rowIdx === -1) return null;
  const row = notice.slice(rowIdx, notice.indexOf('\n', rowIdx));
  const match = row.match(/[0-9a-f]{64}/i);
  return match ? match[0].toLowerCase() : null;
}

export function recordedDigestFromHeader(filePath) {
  const header = readFileSync(filePath, 'utf8').slice(0, 4000);
  const idx = header.indexOf('sha256 of the pristine copy');
  if (idx === -1) return null;
  const window = header.slice(idx, idx + 300);
  const match = window.match(/[0-9a-f]{64}/i);
  return match ? match[0].toLowerCase() : null;
}

/** Real (network-hitting) fetchers. Swapped out for stubs in tests. */
export function fetchLatestVersionFromNpm(packageName = PACKAGE) {
  return execFileSync('npm', ['view', packageName, 'version'], { encoding: 'utf8' }).trim();
}

export function fetchPristineSourceFromNpm(pin, upstreamRelPath, packageName = PACKAGE) {
  const tmp = mkdtempSync(join(tmpdir(), 'noble-pq-'));
  execFileSync('npm', ['pack', `${packageName}@${pin}`, '--silent', '--pack-destination', tmp]);
  const tarball = execFileSync('sh', ['-c', `ls ${tmp}/*.tgz`], { encoding: 'utf8' }).trim();
  execFileSync('tar', ['-xzf', tarball, '-C', tmp]);
  return readFileSync(join(tmp, 'package', upstreamRelPath));
}

/**
 * Core check. Reads the pin and the vendored files' own recorded digests
 * from `coreDir`; everything that would otherwise hit the network goes
 * through `fetchLatestVersion` / `fetchPristineSource`, both overridable.
 */
export function evaluateDrift({
  coreDir = DEFAULT_CORE_DIR,
  pin,
  fetchLatestVersion = fetchLatestVersionFromNpm,
  fetchPristineSource = fetchPristineSourceFromNpm,
  repo = process.env.GITHUB_REPOSITORY ?? 'jeloercc/pqc-sdk',
} = {}) {
  const noticePath = join(coreDir, 'src/vendor/ml-kem/NOTICE.md');
  const files = vendoredFilesFor(coreDir);

  const latest = fetchLatestVersion(PACKAGE);
  const versionDrift = latest !== pin;

  const baselineMismatches = [];
  for (const file of files) {
    const vendoredPath = join(file.dir, file.rel);
    const recorded =
      file.digestSource === 'notice'
        ? recordedDigestFromNotice(noticePath, file.rel)
        : recordedDigestFromHeader(vendoredPath);

    if (!recorded) {
      baselineMismatches.push({
        file: file.rel,
        reason: 'no recorded pristine digest found (NOTICE.md / header format may have changed)',
      });
      continue;
    }

    const fresh = sha256(fetchPristineSource(pin, file.upstream, PACKAGE));
    if (fresh !== recorded) {
      baselineMismatches.push({ file: file.rel, recorded, fresh });
    }
  }

  const hasDrift = versionDrift || baselineMismatches.length > 0;
  const issueTitle = `Vendoring drift: ${PACKAGE}`;
  const reportBody = buildReportBody({ pin, latest, versionDrift, baselineMismatches, repo });

  return { pin, latest, versionDrift, baselineMismatches, hasDrift, issueTitle, reportBody };
}

export function buildReportBody({ pin, latest, versionDrift, baselineMismatches, repo }) {
  const lines = [];
  lines.push('Automated vendoring-drift check for `@noble/post-quantum`.');
  lines.push('');
  if (versionDrift) {
    lines.push(
      `**(a) A newer version is published.** Pinned: \`${pin}\`. Latest on npm: \`${latest}\`.`,
    );
  } else {
    lines.push(`**(a) No newer version.** Pinned \`${pin}\` is the latest published version.`);
  }
  lines.push('');
  if (baselineMismatches.length > 0) {
    lines.push(
      '**(b) A recorded pristine-copy digest no longer matches a fresh copy of upstream at the pinned version.** ' +
        'This means the documented baseline that our modifications are diffed against needs a human look — ' +
        'it may be a stale record, or it may mean a vendored file was edited outside the documented procedure:',
    );
    lines.push('');
    for (const m of baselineMismatches) {
      lines.push(
        m.recorded
          ? `- \`${m.file}\`: recorded \`${m.recorded}\`, fresh fetch \`${m.fresh}\``
          : `- \`${m.file}\`: ${m.reason}`,
      );
    }
  } else {
    lines.push(
      '**(b) No baseline drift.** All recorded pristine-copy digests still match a fresh fetch of upstream.',
    );
  }
  lines.push('');
  lines.push(
    'Affected vendored files: `ml-kem.ts`, `_crystals.ts`, `utils.ts` (under `packages/core/src/vendor/ml-kem/`), `ml-dsa.ts` (under `packages/core/src/vendor/ml-dsa/`).',
  );
  lines.push('');
  lines.push(
    `See [\`${NOTICE_REL}\`](https://github.com/${repo}/blob/main/${NOTICE_REL}) for the re-vendoring procedure and what each file's modifications are — this issue intentionally does not restate it.`,
  );
  lines.push('');
  lines.push(
    'After re-vendoring, the equivalence and zeroization test suites under `packages/core/src/vendor/*/__tests__/` are the tripwire: do not adjust them to match new output.',
  );
  lines.push('');
  lines.push(
    'This check is detect-and-notify only — it never modifies the vendored files or package.json.',
  );
  return lines.join('\n') + '\n';
}

function readPin(coreDir) {
  const corePkg = JSON.parse(readFileSync(join(coreDir, 'package.json'), 'utf8'));
  const pin = corePkg.dependencies?.[PACKAGE];
  if (!pin) {
    throw new Error(`${PACKAGE} not found in packages/core/package.json dependencies`);
  }
  return pin;
}

function main() {
  const reportArgIdx = process.argv.indexOf('--report');
  const reportPath =
    reportArgIdx !== -1
      ? process.argv[reportArgIdx + 1]
      : join(process.cwd(), 'vendor-drift-report.md');

  const coreDir = DEFAULT_CORE_DIR;
  const pin = readPin(coreDir);
  const result = evaluateDrift({ coreDir, pin });

  writeFileSync(reportPath, result.reportBody);

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `has-drift=${result.hasDrift}\n`);
    appendFileSync(process.env.GITHUB_OUTPUT, `issue-title=${result.issueTitle}\n`);
  }

  console.log(result.reportBody);
  console.log(`has-drift=${result.hasDrift}`);
}

// Only run as the CLI entry point — not when __tests__/ imports this module.
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
