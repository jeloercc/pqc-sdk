/**
 * The `zod` peer range must admit only zod releases that provide every zod
 * entry point the built bundle imports. Up to 0.3.4 the range was `>=3.0.0`
 * while the bundle imports `zod/v3`: npm installed zod 3.0–3.24 without a
 * warning, and importing the package then failed with
 * ERR_PACKAGE_PATH_NOT_EXPORTED. Reads dist/: turbo runs this package's
 * `build` before `test` (see turbo.json).
 */

import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

// First zod release from which each entry point imports under Node's ESM
// conditions. zod 3.25.0 lists `./v3` in `exports`, but its tarball lacks
// the file that export points to (dist/esm/v3/index.js), so the import fails
// with ERR_MODULE_NOT_FOUND. 3.25.1 and later, and every 4.x, ship it.
const FIRST_ZOD_RELEASE_WITH: Readonly<Record<string, string>> = {
  zod: '3.0.0',
  'zod/v3': '3.25.1',
};

const PACKAGE_ROOT = new URL('..', import.meta.url);

function parseVersion(version: string): number[] {
  return version.split('.').map((part) => Number(part));
}

function isAtLeast(version: string, minimum: string): boolean {
  const a = parseVersion(version);
  const b = parseVersion(minimum);
  for (let i = 0; i < 3; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

describe('zod peer range', () => {
  it('admits only zod releases that export every zod entry point dist/ imports', async () => {
    const manifest = JSON.parse(await readFile(new URL('package.json', PACKAGE_ROOT), 'utf8')) as {
      peerDependencies: Record<string, string>;
    };
    const bundle = await readFile(new URL('dist/index.js', PACKAGE_ROOT), 'utf8');
    const specifiers = [
      ...new Set(
        [...bundle.matchAll(/\bfrom\s*["'](zod(?:\/[^"']+)?)["']/g)].map((match) => match[1]),
      ),
    ];
    expect(specifiers.length, 'dist/index.js imports no zod entry point').toBeGreaterThan(0);

    const range = manifest.peerDependencies['zod'];
    expect(range, 'zod is not a peer dependency').toBeDefined();

    for (const alternative of (range ?? '').split('||').map((part) => part.trim())) {
      const lowest = /^\^(\d+\.\d+\.\d+)$/.exec(alternative)?.[1];
      expect(lowest, `zod peer alternative "${alternative}" is not a ^X.Y.Z range`).toBeDefined();
      for (const specifier of specifiers) {
        const first = specifier === undefined ? undefined : FIRST_ZOD_RELEASE_WITH[specifier];
        expect(first, `no first zod release recorded for "${String(specifier)}"`).toBeDefined();
        expect(
          isAtLeast(lowest ?? '0.0.0', first ?? '0.0.0'),
          `"${alternative}" admits zod releases without "${String(specifier)}" (first in ${String(first)})`,
        ).toBe(true);
      }
    }
  });
});
