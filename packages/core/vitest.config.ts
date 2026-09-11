import { readFileSync } from 'node:fs';

import { defineConfig } from 'vitest/config';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

export default defineConfig({
  // Tests run against src/, so the constant is injected here just like in tsup.
  define: {
    __PQC_CORE_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    // scripts/**/*.test.mjs covers CI-only tooling (e.g. check-vendor-drift.mjs) that
    // isn't part of the published package and so stays out of the coverage.include below.
    include: ['src/**/*.test.ts', 'scripts/**/*.test.mjs'],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      // src/vendor/** is third-party code copied verbatim from @noble/post-quantum (see
      // src/vendor/ml-kem/NOTICE.md). Its utils.ts serves every noble algorithm, so most
      // of it is unreachable from the ML-KEM surface and would drag the ratios below the
      // thresholds without saying anything about this SDK's own test quality. The local
      // modifications are covered directly by src/vendor/ml-kem/__tests__/.
      exclude: ['src/**/*.test.ts', 'src/**/*.bench.ts', 'src/vendor/**'],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
    },
  },
});
