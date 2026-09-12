import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { VECTOR_FILE_NAMES, buildReportBody, evaluateDrift } from '../check-circl-drift.mjs';

/**
 * Builds a minimal src/vectors/interop-shaped fixture: the three real vector
 * file names, each carrying just enough of a `meta` block for
 * check-circl-drift.mjs to read — mirroring the real files' shape closely
 * enough that the check's logic runs unmodified against it.
 */
function makeFixture(counterpartVersion, { inconsistentXwing = false } = {}) {
  const vectorsDir = mkdtempSync(join(tmpdir(), 'circl-drift-fixture-'));
  mkdirSync(vectorsDir, { recursive: true });

  const regenerateCommand =
    'cd packages/core && pnpm build && ' +
    '(cd scripts/interop/circl-helper && go build -o circl-helper .) && ' +
    'pnpm exec tsx scripts/interop/generate-circl-vectors.mts';

  for (const name of VECTOR_FILE_NAMES) {
    const version =
      inconsistentXwing && name === 'circl-xwing.json' ? 'v1.6.4' : counterpartVersion;
    writeFileSync(
      join(vectorsDir, name),
      JSON.stringify({
        meta: {
          generatedWith: '@pqc-sdk/core@0.9.2',
          counterpart: 'github.com/cloudflare/circl',
          counterpartVersion: version,
          generatedAt: '2026-09-12T18:00:19.325Z',
          regenerateCommand,
          note: 'fixture vector — not real cross-check output',
        },
        case: {},
      }),
    );
  }

  return { vectorsDir, regenerateCommand };
}

describe('check-circl-drift: evaluateDrift', () => {
  const fixtureDirs = [];

  afterEach(() => {
    while (fixtureDirs.length > 0) {
      const dir = fixtureDirs.pop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports no drift when the recorded version matches latest', async () => {
    const { vectorsDir } = makeFixture('v1.6.5');
    fixtureDirs.push(vectorsDir);

    const result = await evaluateDrift({
      vectorsDir,
      fetchLatestVersion: () => 'v1.6.5',
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(false);
    expect(result.versionDrift).toBe(false);
    expect(result.inconsistent).toBe(false);
    expect(result.reportBody).toContain('No newer CIRCL release.');
  });

  it('flags drift and names the newer version when a newer CIRCL release exists', async () => {
    const { vectorsDir, regenerateCommand } = makeFixture('v1.6.5');
    fixtureDirs.push(vectorsDir);

    const result = await evaluateDrift({
      vectorsDir,
      fetchLatestVersion: () => 'v1.7.0',
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(true);
    expect(result.versionDrift).toBe(true);
    expect(result.issueTitle).toBe('Interop-vector drift: github.com/cloudflare/circl');
    expect(result.reportBody).toContain('A newer CIRCL release is published.');
    expect(result.reportBody).toContain('Vectors recorded: `v1.6.5`');
    expect(result.reportBody).toContain('Latest: `v1.7.0`');
    expect(result.reportBody).toContain(regenerateCommand);
    expect(result.reportBody).toContain('finding to investigate, not a test to fix');
  });

  it('flags an inconsistency when the three vector files disagree on the recorded version', async () => {
    const { vectorsDir } = makeFixture('v1.6.5', { inconsistentXwing: true });
    fixtureDirs.push(vectorsDir);

    const result = await evaluateDrift({
      vectorsDir,
      fetchLatestVersion: () => 'v1.6.5',
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(true);
    expect(result.inconsistent).toBe(true);
    expect(result.reportBody).toContain('disagree on which CIRCL version');
    expect(result.reportBody).toContain('`circl-xwing.json`: `v1.6.4`');
    expect(result.reportBody).toContain('`circl-mldsa.json`: `v1.6.5`');
  });

  it('never invokes the real proxy-hitting fetcher when a stub is supplied', async () => {
    const { vectorsDir } = makeFixture('v1.6.5');
    fixtureDirs.push(vectorsDir);

    let calls = 0;
    await evaluateDrift({
      vectorsDir,
      fetchLatestVersion: () => {
        calls += 1;
        return 'v1.6.5';
      },
      repo: 'jeloercc/pqc-sdk',
    });

    expect(calls).toBe(1);
  });
});

describe('check-circl-drift: buildReportBody', () => {
  it('always states the detect-and-notify boundary, drift or not', () => {
    const body = buildReportBody({
      recorded: 'v1.6.5',
      latest: 'v1.6.5',
      versionDrift: false,
      inconsistent: false,
      metas: [],
      regenerateCommand: 'echo test',
      repo: 'jeloercc/pqc-sdk',
    });
    expect(body).toContain('detect-and-notify only');
    expect(body).toContain('never regenerates the vectors');
  });
});
