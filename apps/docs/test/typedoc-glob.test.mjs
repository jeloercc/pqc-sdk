import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { Application, ReflectionKind, TSConfigReader } from 'typedoc';

async function documentedNames(t, entryPoint, exclude = []) {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-typedoc-glob-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const files = {
    'src/index.ts': 'export interface RootEntry { value: string }',
    'src/nested/child.ts': 'export function nestedEntry(): string { return "nested"; }',
    'src/other.tsx': 'export type OtherEntry = string;',
    'src/node_modules/ignored.ts': 'export interface IgnoredDependency {}',
    'src/.hidden/hidden.ts': 'export interface HiddenEntry {}',
  };
  for (const [name, content] of Object.entries(files)) {
    const path = join(directory, name);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
  }
  const tsconfig = join(directory, 'tsconfig.json');
  await writeFile(
    tsconfig,
    JSON.stringify({
      compilerOptions: {
        strict: true,
        target: 'ES2022',
        module: 'ESNext',
        moduleResolution: 'Bundler',
        types: [],
      },
      include: ['src/**/*'],
    }),
  );
  const app = await Application.bootstrap(
    {
      entryPoints: [join(directory, entryPoint)],
      entryPointStrategy: 'expand',
      tsconfig,
      exclude,
      name: 'Glob fixture',
      logLevel: 'Error',
    },
    [new TSConfigReader()],
  );
  const project = await app.convert();
  assert.equal(
    app.logger.hasErrors(),
    false,
    'TypeDoc must not report configuration or conversion errors',
  );
  assert.ok(project, 'TypeDoc must convert the fixture project');
  return project
    .getReflectionsByKind(
      ReflectionKind.Interface | ReflectionKind.Function | ReflectionKind.TypeAlias,
    )
    .map((reflection) => reflection.name)
    .sort();
}

test('discovers nested TypeScript entries without dependencies or hidden directories', async (t) => {
  assert.deepEqual(await documentedNames(t, 'src/**/*.ts'), ['RootEntry', 'nestedEntry']);
});

test('expands brace patterns without descending into nested entries', async (t) => {
  assert.deepEqual(await documentedNames(t, 'src/*.{ts,tsx}'), ['OtherEntry', 'RootEntry']);
});

test('preserves configured exclusion patterns during discovery', async (t) => {
  assert.deepEqual(await documentedNames(t, 'src/**/*.ts', ['**/nested/**']), ['RootEntry']);
});

test('discovers an exact entry point', async (t) => {
  assert.deepEqual(await documentedNames(t, 'src/index.ts'), ['RootEntry']);
});
