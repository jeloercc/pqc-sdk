/**
 * Consumer-side type check of the published declarations: compiles a strict
 * `nodenext` project that imports the built package by name, the way a
 * downstream TypeScript user does. Guards against shipping a `types` entry
 * with no declaration file behind it. `pnpm test` builds dist/ first.
 */

import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const TSC = createRequire(import.meta.url).resolve('typescript/lib/tsc.js');

const CONSUMER = `
import type { SecretKey } from '@pqc-sdk/core';
import {
  type CreatePqcToolsOptions,
  KEY_ID_PATTERN,
  createPqcTools,
  pqcAlgorithmsTool,
  pqcEncryptTool,
  pqcVerifyTool,
} from '@pqc-sdk/langchain';

const vault = new Map<string, SecretKey>();
const options: CreatePqcToolsOptions = {
  resolveSecretKey: async (keyId: string): Promise<SecretKey> => {
    const key = vault.get(keyId);
    if (!key) throw new Error('unknown key');
    return key;
  },
  onSecretKey: (keyId: string, secretKey: SecretKey): void => {
    vault.set(keyId, secretKey);
  },
  enableSign: true,
};
const names: string[] = createPqcTools(options).map((tool) => tool.name);
const standalone: string[] = [pqcEncryptTool.name, pqcVerifyTool.name, pqcAlgorithmsTool.name];
const valid: boolean = KEY_ID_PATTERN.test('alice');
export { names, standalone, valid };
`;

let consumer: string;

beforeAll(async () => {
  consumer = await mkdtemp(join(tmpdir(), 'pqc-langchain-types-'));
  const scope = join(consumer, 'node_modules', '@pqc-sdk');
  await mkdir(scope, { recursive: true });
  await symlink(PACKAGE_ROOT, join(scope, 'langchain'), 'dir');
  await symlink(join(PACKAGE_ROOT, 'node_modules', '@pqc-sdk', 'core'), join(scope, 'core'), 'dir');
  await writeFile(join(consumer, 'package.json'), JSON.stringify({ type: 'module' }));
  await writeFile(join(consumer, 'consumer.ts'), CONSUMER);
  await writeFile(
    join(consumer, 'tsconfig.json'),
    JSON.stringify({
      compilerOptions: {
        strict: true,
        exactOptionalPropertyTypes: true,
        module: 'nodenext',
        moduleResolution: 'nodenext',
        target: 'es2022',
        noEmit: true,
        skipLibCheck: true,
        types: [],
      },
      files: ['consumer.ts'],
    }),
  );
});

afterAll(async () => {
  await rm(consumer, { recursive: true, force: true });
});

describe('published type declarations', () => {
  it('type-check a strict nodenext consumer', () => {
    let output = '';
    try {
      execFileSync(process.execPath, [TSC, '-p', consumer], { encoding: 'utf8' });
    } catch (cause) {
      output = String((cause as { stdout?: unknown }).stdout ?? cause);
    }
    expect(output).toBe('');
  }, 60_000);
});
