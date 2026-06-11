import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { pqc } from '@pqc-sdk/core';
import { describe, expect, it } from 'vitest';

const exec = promisify(execFile);
const CLI = fileURLToPath(new URL('../dist/index.js', import.meta.url));

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function runCli(args: string[], cwd: string): Promise<CliResult> {
  // Entorno sin TTY ni señales de CI: picocolors debe desactivar los colores.
  const env = { ...process.env };
  delete env.CI;
  delete env.FORCE_COLOR;
  delete env.GITHUB_ACTIONS;
  try {
    const { stdout, stderr } = await exec(process.execPath, [CLI, ...args], { cwd, env });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

const freshDir = () => mkdtemp(join(tmpdir(), 'pqc-cli-'));

describe('binario pqc', () => {
  it('tiene shebang para ejecutarse vía npx', async () => {
    const dist = await readFile(CLI, 'utf8');
    expect(dist.startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('--help lista los comandos y sale con 0', async () => {
    const result = await runCli(['--help'], await freshDir());

    expect(result.code).toBe(0);
    const output = result.stdout + result.stderr;
    expect(output).toContain('init');
    expect(output).toContain('keygen');
    expect(output).toContain('audit');
  });

  it('no emite códigos ANSI sin TTY (apto para CI)', async () => {
    const dir = await freshDir();
    const result = await runCli(['init'], dir);

    // eslint-disable-next-line no-control-regex
    expect(result.stdout + result.stderr).not.toMatch(/\[/);
  });
});

describe('pqc init', () => {
  it('crea config, keys de desarrollo y example.ts', async () => {
    const dir = await freshDir();
    const result = await runCli(['init'], dir);

    expect(result.code).toBe(0);

    const config = JSON.parse(await readFile(join(dir, 'pqc.config.json'), 'utf8')) as {
      defaultAlgorithm: string;
    };
    expect(config.defaultAlgorithm).toBe('ml-kem-768');

    const publicKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.public.pqc'), 'utf8')).trim(),
    );
    const secretKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.secret.pqc'), 'utf8')).trim(),
    );
    expect(publicKey.algorithm).toBe('ml-kem-768');
    expect(publicKey.use).toBe('public');
    expect(secretKey.use).toBe('secret');

    const example = await readFile(join(dir, 'example.ts'), 'utf8');
    expect(example).toContain('@pqc-sdk/core');
    expect(example).toContain('pqc.encrypt');
    expect(example).toContain('pqc.decrypt');
  });

  it('las keys de desarrollo funcionan para un roundtrip real', async () => {
    const dir = await freshDir();
    await runCli(['init'], dir);

    const publicKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.public.pqc'), 'utf8')).trim(),
    );
    const secretKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.secret.pqc'), 'utf8')).trim(),
    );

    const ciphertext = await pqc.encrypt('init e2e', publicKey as never);
    const plaintext = await pqc.decrypt(ciphertext, secretKey as never);
    expect(new TextDecoder().decode(plaintext)).toBe('init e2e');
  });

  it('advierte que las keys NO son para producción', async () => {
    const result = await runCli(['init'], await freshDir());

    expect(result.stdout + result.stderr).toMatch(/no.{0,30}producción/i);
  });

  it('se niega a reinicializar un proyecto existente', async () => {
    const dir = await freshDir();
    await runCli(['init'], dir);
    const second = await runCli(['init'], dir);

    expect(second.code).not.toBe(0);
    expect(second.stdout + second.stderr).toMatch(/ya (existe|está inicializado)/i);
  });
});

describe('pqc keygen', () => {
  it('genera ML-KEM-768 en ./keys por defecto', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-kem-768');
    await readFile(join(dir, 'keys/ml-kem-768.secret.pqc'), 'utf8');
  });

  it('respeta --algorithm y --out', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen', '--algorithm', 'ml-dsa-65', '--out', 'firma/'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'firma/ml-dsa-65.secret.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-dsa-65');
    expect(key.use).toBe('secret');
  });

  it('rechaza algoritmos desconocidos', async () => {
    const result = await runCli(['keygen', '--algorithm', 'rsa-2048'], await freshDir());

    expect(result.code).not.toBe(0);
    expect(result.stdout + result.stderr).toMatch(/no soportado|UNSUPPORTED/i);
  });

  it('no pisa keys existentes sin --force', async () => {
    const dir = await freshDir();
    await runCli(['keygen'], dir);
    const original = await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8');

    const second = await runCli(['keygen'], dir);
    expect(second.code).not.toBe(0);
    expect(await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8')).toBe(original);

    const forced = await runCli(['keygen', '--force'], dir);
    expect(forced.code).toBe(0);
    expect(await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8')).not.toBe(original);
  });
});

describe('pqc audit', () => {
  it('proyecto limpio: exit 0 y mensaje claro', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'limpio' }));
    await writeFile(join(dir, 'index.js'), 'console.log("sin crypto");\n');

    const result = await runCli(['audit'], dir);

    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/sin (uso de )?crypto pre-cuántic/i);
  });

  it('detecta dependencias y código pre-cuántico con su equivalente PQC', async () => {
    const dir = await freshDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'legacy', dependencies: { jsonwebtoken: '^9.0.0' } }),
    );
    await mkdir(join(dir, 'src'));
    await writeFile(
      join(dir, 'src/auth.js'),
      [
        "const { createSign, createECDH } = require('node:crypto');",
        "const jwt = require('jsonwebtoken');",
        "jwt.sign(payload, key, { algorithm: 'RS256' });",
        "const signer = createSign('RSA-SHA256');",
        "const ecdh = createECDH('prime256v1');",
      ].join('\n'),
    );

    const result = await runCli(['audit'], dir);

    expect(result.code).not.toBe(0);
    expect(result.stdout).toContain('jsonwebtoken');
    expect(result.stdout).toContain('src/auth.js');
    expect(result.stdout).toContain('ML-DSA-65');
    expect(result.stdout).toContain('ML-KEM-768');
  });

  it('ignora node_modules y dist', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'limpio' }));
    await mkdir(join(dir, 'node_modules/lib'), { recursive: true });
    await writeFile(join(dir, 'node_modules/lib/index.js'), "createSign('RSA-SHA256');");

    const result = await runCli(['audit'], dir);

    expect(result.code).toBe(0);
  });
});
