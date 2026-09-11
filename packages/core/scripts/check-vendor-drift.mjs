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
 */
import { execFileSync } from 'node:child_process';
import console from 'node:console';
import { createHash } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const PACKAGE = '@noble/post-quantum';
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const CORE_DIR = join(SCRIPT_DIR, '..');
const VENDOR_KEM_DIR = join(CORE_DIR, 'src/vendor/ml-kem');
const VENDOR_DSA_DIR = join(CORE_DIR, 'src/vendor/ml-dsa');
const NOTICE_PATH = join(VENDOR_KEM_DIR, 'NOTICE.md');
const NOTICE_REL = 'packages/core/src/vendor/ml-kem/NOTICE.md';

const VENDORED_FILES = [
  { rel: 'ml-kem.ts', dir: VENDOR_KEM_DIR, upstream: 'src/ml-kem.ts' },
  { rel: '_crystals.ts', dir: VENDOR_KEM_DIR, upstream: 'src/_crystals.ts' },
  { rel: 'utils.ts', dir: VENDOR_KEM_DIR, upstream: 'src/utils.ts' },
  { rel: 'ml-dsa.ts', dir: VENDOR_DSA_DIR, upstream: 'src/ml-dsa.ts' },
];

function sh(cmd, args) {
  return execFileSync(cmd, args, { encoding: 'utf8' }).trim();
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** Pulls the first 64-hex-char run following a "sha256 of the pristine copy" label near `anchor`. */
function findRecordedDigest(text, anchor) {
  const idx = text.indexOf(anchor);
  if (idx === -1) return null;
  const window = text.slice(idx, idx + 300);
  const match = window.match(/[0-9a-f]{64}/i);
  return match ? match[0].toLowerCase() : null;
}

function recordedDigestFromNotice(fileName) {
  const notice = readFileSync(NOTICE_PATH, 'utf8');
  const rowIdx = notice.indexOf(`\`${fileName}\``);
  if (rowIdx === -1) return null;
  const row = notice.slice(rowIdx, notice.indexOf('\n', rowIdx));
  const match = row.match(/[0-9a-f]{64}/i);
  return match ? match[0].toLowerCase() : null;
}

function recordedDigestFromHeader(filePath) {
  const header = readFileSync(filePath, 'utf8').slice(0, 4000);
  return findRecordedDigest(header, 'sha256 of the pristine copy');
}

function main() {
  const reportArgIdx = process.argv.indexOf('--report');
  const reportPath =
    reportArgIdx !== -1 ? process.argv[reportArgIdx + 1] : join(process.cwd(), 'vendor-drift-report.md');

  const corePkg = JSON.parse(readFileSync(join(CORE_DIR, 'package.json'), 'utf8'));
  const pin = corePkg.dependencies?.[PACKAGE];
  if (!pin) {
    throw new Error(`${PACKAGE} not found in packages/core/package.json dependencies`);
  }

  const latest = sh('npm', ['view', PACKAGE, 'version']);
  const versionDrift = latest !== pin;

  // Fetch the *pinned* version's pristine source and re-check the recorded digests.
  const tmp = mkdtempSync(join(tmpdir(), 'noble-pq-'));
  sh('npm', ['pack', `${PACKAGE}@${pin}`, '--silent', '--pack-destination', tmp]);
  const tarball = sh('sh', ['-c', `ls ${tmp}/*.tgz`]);
  sh('tar', ['-xzf', tarball, '-C', tmp]);

  const baselineMismatches = [];
  for (const file of VENDORED_FILES) {
    const vendoredPath = join(file.dir, file.rel);
    const upstreamPath = join(tmp, 'package', file.upstream);

    const recorded =
      file.dir === VENDOR_KEM_DIR
        ? recordedDigestFromNotice(file.rel)
        : recordedDigestFromHeader(vendoredPath);
    if (!recorded) {
      baselineMismatches.push({
        file: file.rel,
        reason: 'no recorded pristine digest found (NOTICE.md / header format may have changed)',
      });
      continue;
    }

    const fresh = sha256(readFileSync(upstreamPath));
    if (fresh !== recorded) {
      baselineMismatches.push({ file: file.rel, recorded, fresh });
    }
  }

  const hasDrift = versionDrift || baselineMismatches.length > 0;

  const lines = [];
  lines.push('Automated vendoring-drift check for `@noble/post-quantum`.');
  lines.push('');
  if (versionDrift) {
    lines.push(`**(a) A newer version is published.** Pinned: \`${pin}\`. Latest on npm: \`${latest}\`.`);
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
    lines.push('**(b) No baseline drift.** All recorded pristine-copy digests still match a fresh fetch of upstream.');
  }
  lines.push('');
  lines.push('Affected vendored files: `ml-kem.ts`, `_crystals.ts`, `utils.ts` (under `packages/core/src/vendor/ml-kem/`), `ml-dsa.ts` (under `packages/core/src/vendor/ml-dsa/`).');
  lines.push('');
  const repo = process.env.GITHUB_REPOSITORY ?? 'jeloercc/pqc-sdk';
  lines.push(
    `See [\`${NOTICE_REL}\`](https://github.com/${repo}/blob/main/${NOTICE_REL}) for the re-vendoring procedure and what each file's modifications are — this issue intentionally does not restate it.`,
  );
  lines.push('');
  lines.push(
    'After re-vendoring, the equivalence and zeroization test suites under `packages/core/src/vendor/*/__tests__/` are the tripwire: do not adjust them to match new output.',
  );
  lines.push('');
  lines.push('This check is detect-and-notify only — it never modifies the vendored files or package.json.');

  writeFileSync(reportPath, lines.join('\n') + '\n');

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `has-drift=${hasDrift}\n`);
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `issue-title=Vendoring drift: ${PACKAGE}\n`,
    );
  }

  console.log(lines.join('\n'));
  console.log(`\nhas-drift=${hasDrift}`);
}

main();
