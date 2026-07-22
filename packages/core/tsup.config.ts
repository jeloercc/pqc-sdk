import { readFileSync } from 'node:fs';

import { defineConfig } from 'tsup';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

export default defineConfig({
  // src/stream.ts is not part of the public @pqc-sdk/core surface yet
  // (package.json "exports" only maps "."; docs/proposals/streaming-encryption.md
  // Day 3 exports it from index.ts) — built as a second entry purely so
  // scripts/generate-golden-vectors-streaming.mjs can import compiled JS via
  // a relative dist path, the same way the other golden-vector scripts do.
  entry: ['src/index.ts', 'src/stream.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  define: {
    __PQC_CORE_VERSION__: JSON.stringify(pkg.version),
  },
});
