#!/usr/bin/env node
// Type-checks every ```ts block in README.md against the built packages.
//
// Each block is compiled as its own module under the repo's strict settings,
// with `@pqc-sdk/core` and `@pqc-sdk/langchain` resolved to their built
// declarations (dist/index.d.ts) — the same types a consumer gets from npm.
// Run after `pnpm build`; wired into `turbo run lint` as `//#check:readme`.
//
// Identifiers a snippet uses without defining (an LLM instance, a framework
// the repo does not depend on) are declared in AMBIENT below. Keep that list
// small: a stub only stands in for code outside this repo, never for our API.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const README = join(ROOT, 'README.md');
const WORK = join(ROOT, 'node_modules', '.cache', 'readme-snippets');

const PACKAGES = {
  '@pqc-sdk/core': join(ROOT, 'packages/core/dist/index.d.ts'),
  '@pqc-sdk/langchain': join(ROOT, 'packages/langchain/dist/index.d.ts'),
};

// TypeScript and @types/node resolve through a workspace package that
// depends on both (pnpm does not hoist them to the root).
const requireFromWorkspace = createRequire(join(ROOT, 'packages/langchain/package.json'));
const TSC = requireFromWorkspace.resolve('typescript/lib/tsc.js');
const TYPE_ROOTS = dirname(dirname(requireFromWorkspace.resolve('@types/node/package.json')));

const AMBIENT = `
// Stand-ins for code outside this repo that README snippets refer to.
declare const model: unknown; // the LLM instance the reader brings
declare module '@langchain/langgraph/prebuilt' {
  export function createReactAgent(options: { llm: unknown; tools: unknown[] }): unknown;
}
`;

for (const [name, path] of Object.entries(PACKAGES)) {
  if (!existsSync(path)) {
    console.error(`check-readme-snippets: ${name} is not built (${relative(ROOT, path)} missing).`);
    console.error('Run `pnpm build` first.');
    process.exit(1);
  }
}

/** Extracts ```ts blocks with the README line each one's code starts on. */
function extractSnippets(markdown) {
  const snippets = [];
  const lines = markdown.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() !== '```ts') continue;
    const start = i + 1;
    let end = start;
    while (end < lines.length && lines[end].trim() !== '```') end++;
    snippets.push({ startLine: start + 1, code: lines.slice(start, end).join('\n') });
    i = end;
  }
  return snippets;
}

const snippets = extractSnippets(readFileSync(README, 'utf8'));
if (snippets.length === 0) {
  console.error('check-readme-snippets: no ```ts blocks found in README.md.');
  process.exit(1);
}

rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });
const files = snippets.map((snippet, index) => {
  const file = `snippet-${index + 1}.ts`;
  // `export {}` keeps each block a module even if it has no imports.
  writeFileSync(join(WORK, file), `${snippet.code}\nexport {};\n`);
  return file;
});
writeFileSync(join(WORK, 'ambient.d.ts'), AMBIENT);
writeFileSync(
  join(WORK, 'tsconfig.json'),
  JSON.stringify(
    {
      compilerOptions: {
        strict: true,
        exactOptionalPropertyTypes: true,
        noUncheckedIndexedAccess: true,
        target: 'ES2022',
        module: 'ESNext',
        moduleResolution: 'Bundler',
        lib: ['ES2022'],
        typeRoots: [TYPE_ROOTS],
        types: ['node'],
        noEmit: true,
        skipLibCheck: true,
        paths: Object.fromEntries(Object.entries(PACKAGES).map(([name, path]) => [name, [path]])),
      },
      files: ['ambient.d.ts', ...files],
    },
    null,
    2,
  ),
);

try {
  execFileSync(process.execPath, [TSC, '-p', WORK, '--pretty', 'false'], { encoding: 'utf8' });
} catch (error) {
  const output = String(error.stdout ?? error);
  // Map "snippet-N.ts(line,col)" back to README.md line numbers.
  const mapped = output.replace(
    /(?:[^\s(]*[\\/])?snippet-(\d+)\.ts\((\d+),(\d+)\)/g,
    (_, n, line, col) => {
      const snippet = snippets[Number(n) - 1];
      return `README.md:${snippet.startLine + Number(line) - 1}:${col}`;
    },
  );
  console.error(`check-readme-snippets: README.md code does not type-check:\n\n${mapped}`);
  process.exit(1);
}

console.log(`check-readme-snippets: ${snippets.length} README.md ts block(s) type-check.`);
