import { Buffer } from 'node:buffer';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { PACKAGE, evaluateDrift, sha256 } from '../check-vendor-drift.mjs';

/**
 * Builds a minimal packages/core-shaped fixture: a package.json pinning
 * PACKAGE, a NOTICE.md carrying the ml-kem.ts/_crystals.ts/utils.ts pristine
 * digests, and an ml-dsa.ts carrying its own digest in its header comment —
 * mirroring the real files' format closely enough for the regexes in
 * check-vendor-drift.mjs to parse them the same way.
 */
function makeFixture(pin) {
  const coreDir = mkdtempSync(join(tmpdir(), 'vendor-drift-fixture-'));
  const kemDir = join(coreDir, 'src/vendor/ml-kem');
  const dsaDir = join(coreDir, 'src/vendor/ml-dsa');
  mkdirSync(kemDir, { recursive: true });
  mkdirSync(dsaDir, { recursive: true });

  writeFileSync(
    join(coreDir, 'package.json'),
    JSON.stringify({ dependencies: { [PACKAGE]: pin } }),
  );

  const upstream = {
    'ml-kem.ts': 'fixture upstream ml-kem content',
    '_crystals.ts': 'fixture upstream _crystals content',
    'utils.ts': 'fixture upstream utils content',
    'ml-dsa.ts': 'fixture upstream ml-dsa content',
  };
  const digests = Object.fromEntries(
    Object.entries(upstream).map(([name, content]) => [name, sha256(Buffer.from(content))]),
  );

  writeFileSync(
    join(kemDir, 'NOTICE.md'),
    [
      '# Third-party notice — vendored ML-KEM',
      '',
      '| File | Upstream path | sha256 of the pristine copy, before local edits |',
      '| --- | --- | --- |',
      `| \`ml-kem.ts\` | \`src/ml-kem.ts\` | \`${digests['ml-kem.ts']}\` |`,
      `| \`_crystals.ts\` | \`src/_crystals.ts\` | \`${digests['_crystals.ts']}\` |`,
      `| \`utils.ts\` | \`src/utils.ts\` | \`${digests['utils.ts']}\` |`,
      '',
    ].join('\n'),
  );

  for (const name of ['ml-kem.ts', '_crystals.ts', 'utils.ts']) {
    writeFileSync(join(kemDir, name), `// vendored fixture copy of ${name}\n`);
  }

  writeFileSync(
    join(dsaDir, 'ml-dsa.ts'),
    [
      '/*',
      ' * VENDORED — do not edit to "improve" it.',
      ' * sha256 of the pristine copy, before local edits:',
      ` *   ${digests['ml-dsa.ts']}`,
      ' */',
      '',
    ].join('\n'),
  );

  return { coreDir, upstream, digests };
}

/** A fetchPristineSource stub keyed by the upstream file's basename, no network involved. */
function stubFetcherFor(contentByName) {
  return (_pin, upstreamRelPath) => {
    const name = upstreamRelPath.split('/').pop();
    const content = contentByName[name];
    if (content === undefined) {
      throw new Error(`stub has no fixture content for ${upstreamRelPath}`);
    }
    return Buffer.from(content);
  };
}

describe('check-vendor-drift: evaluateDrift', () => {
  const fixtureDirs = [];

  afterEach(() => {
    while (fixtureDirs.length > 0) {
      const dir = fixtureDirs.pop();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports no drift when the pin matches latest and every digest matches upstream', () => {
    const pin = '0.7.1';
    const { coreDir, upstream } = makeFixture(pin);
    fixtureDirs.push(coreDir);

    const result = evaluateDrift({
      coreDir,
      pin,
      fetchLatestVersion: () => pin,
      fetchPristineSource: stubFetcherFor(upstream),
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(false);
    expect(result.versionDrift).toBe(false);
    expect(result.baselineMismatches).toEqual([]);
    expect(result.reportBody).toContain('(a) No newer version.');
    expect(result.reportBody).toContain('(b) No baseline drift.');
  });

  it('flags drift and names the newer version when a newer release exists on npm', () => {
    const pin = '0.7.1';
    const { coreDir, upstream } = makeFixture(pin);
    fixtureDirs.push(coreDir);

    const result = evaluateDrift({
      coreDir,
      pin,
      fetchLatestVersion: () => '0.8.0',
      fetchPristineSource: stubFetcherFor(upstream),
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(true);
    expect(result.versionDrift).toBe(true);
    expect(result.baselineMismatches).toEqual([]);
    expect(result.issueTitle).toBe(`Vendoring drift: ${PACKAGE}`);
    expect(result.reportBody).toContain('(a) A newer version is published.');
    expect(result.reportBody).toContain('Pinned: `0.7.1`');
    expect(result.reportBody).toContain('Latest on npm: `0.8.0`');
    expect(result.reportBody).toContain('(b) No baseline drift.');
  });

  it('flags baseline drift and names the file when a fresh fetch no longer matches the recorded digest', () => {
    const pin = '0.7.1';
    const { coreDir, upstream } = makeFixture(pin);
    fixtureDirs.push(coreDir);

    const tampered = { ...upstream, 'ml-kem.ts': 'unexpected hand-edited upstream content' };

    const result = evaluateDrift({
      coreDir,
      pin,
      fetchLatestVersion: () => pin,
      fetchPristineSource: stubFetcherFor(tampered),
      repo: 'jeloercc/pqc-sdk',
    });

    expect(result.hasDrift).toBe(true);
    expect(result.versionDrift).toBe(false);
    expect(result.baselineMismatches).toHaveLength(1);
    expect(result.baselineMismatches[0].file).toBe('ml-kem.ts');
    expect(result.baselineMismatches[0].recorded).not.toBe(result.baselineMismatches[0].fresh);
    expect(result.reportBody).toContain('(a) No newer version.');
    expect(result.reportBody).toContain('needs a human look');
    expect(result.reportBody).toContain('`ml-kem.ts`: recorded');
    // The other three files' digests were untouched, so they must not be reported.
    expect(result.reportBody).not.toContain('`_crystals.ts`: recorded');
    expect(result.reportBody).not.toContain('`utils.ts`: recorded');
    expect(result.reportBody).not.toContain('`ml-dsa.ts`: recorded');
  });

  it('never invokes the real npm-hitting fetchers when stubs are supplied', () => {
    const pin = '0.7.1';
    const { coreDir, upstream } = makeFixture(pin);
    fixtureDirs.push(coreDir);

    let latestCalls = 0;
    let pristineCalls = 0;

    evaluateDrift({
      coreDir,
      pin,
      fetchLatestVersion: () => {
        latestCalls += 1;
        return pin;
      },
      fetchPristineSource: (...args) => {
        pristineCalls += 1;
        return stubFetcherFor(upstream)(...args);
      },
      repo: 'jeloercc/pqc-sdk',
    });

    expect(latestCalls).toBe(1);
    expect(pristineCalls).toBe(4); // ml-kem.ts, _crystals.ts, utils.ts, ml-dsa.ts
  });
});
