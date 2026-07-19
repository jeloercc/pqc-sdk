import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdtemp, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
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
  // Environment without TTY or CI signals: picocolors must disable colors.
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

describe('pqc binary', () => {
  it('has a shebang so it runs via npx', async () => {
    const dist = await readFile(CLI, 'utf8');
    expect(dist.startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('--version reflects the package.json version', async () => {
    const pkg = JSON.parse(
      await readFile(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
    ) as { version: string };

    const result = await runCli(['--version'], await freshDir());

    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(pkg.version);
  });

  it('--help lists the commands and exits with 0', async () => {
    const result = await runCli(['--help'], await freshDir());

    expect(result.code).toBe(0);
    const output = result.stdout + result.stderr;
    expect(output).toContain('init');
    expect(output).toContain('keygen');
    expect(output).toContain('audit');
  });

  it('emits no ANSI codes without a TTY (CI-friendly)', async () => {
    const dir = await freshDir();
    const result = await runCli(['init'], dir);

    // eslint-disable-next-line no-control-regex
    expect(result.stdout + result.stderr).not.toMatch(/\[/);
  });
});

describe('pqc init', () => {
  it('creates config, development keys and example.ts', async () => {
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

  it('development keys work for a real roundtrip', async () => {
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

  it('warns that the keys are NOT for production', async () => {
    const result = await runCli(['init'], await freshDir());

    expect(result.stdout + result.stderr).toMatch(/NOT.{0,30}production/i);
  });

  it('refuses to reinitialize an existing project', async () => {
    const dir = await freshDir();
    await runCli(['init'], dir);
    const second = await runCli(['init'], dir);

    expect(second.code).not.toBe(0);
    expect(second.stdout + second.stderr).toMatch(/already (exists|initialized)/i);
  });

  it('writes a .gitignore that excludes secret keys', async () => {
    const dir = await freshDir();
    const result = await runCli(['init'], dir);

    expect(result.code).toBe(0);
    const gitignore = await readFile(join(dir, '.gitignore'), 'utf8');
    expect(gitignore).toContain('keys/');
    expect(gitignore).toContain('*.secret.pqc');
  });

  it('appends key patterns to an existing .gitignore without dropping its content', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, '.gitignore'), 'node_modules/\n');

    const result = await runCli(['init'], dir);

    expect(result.code).toBe(0);
    const gitignore = await readFile(join(dir, '.gitignore'), 'utf8');
    expect(gitignore).toContain('node_modules/');
    expect(gitignore).toContain('*.secret.pqc');
  });

  it('does not overwrite an existing example.ts', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'example.ts'), '// my own example\n');

    const result = await runCli(['init'], dir);

    expect(result.code).toBe(0);
    expect(await readFile(join(dir, 'example.ts'), 'utf8')).toBe('// my own example\n');
    expect(result.stdout + result.stderr).toMatch(/example\.ts already exists/i);
  });
});

describe('pqc keygen', () => {
  it('generates ML-KEM-768 in ./keys by default', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-kem-768');
    await readFile(join(dir, 'keys/ml-kem-768.secret.pqc'), 'utf8');
  });

  it('honors --algorithm and --out', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen', '--algorithm', 'ml-dsa-65', '--out', 'signing/'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'signing/ml-dsa-65.secret.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-dsa-65');
    expect(key.use).toBe('secret');
  });

  it('rejects unknown algorithms', async () => {
    const result = await runCli(['keygen', '--algorithm', 'rsa-2048'], await freshDir());

    expect(result.code).not.toBe(0);
    expect(result.stdout + result.stderr).toMatch(/unsupported/i);
  });

  it('honors --name as the base file name (overriding the algorithm default)', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen', '--name', 'payments'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/payments.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-kem-768');
    await readFile(join(dir, 'keys/payments.secret.pqc'), 'utf8');
  });

  it('rejects --name with path separators or traversal', async () => {
    const slash = await runCli(['keygen', '--name', 'sub/payments'], await freshDir());
    expect(slash.code).not.toBe(0);
    expect(slash.stdout + slash.stderr).toMatch(/invalid.*name/i);

    const traversal = await runCli(['keygen', '--name', '../escape'], await freshDir());
    expect(traversal.code).not.toBe(0);
    expect(traversal.stdout + traversal.stderr).toMatch(/invalid.*name/i);
  });

  it('does not overwrite existing keys without --force', async () => {
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

  it('protects secret keys with .gitignore and does not duplicate patterns', async () => {
    const dir = await freshDir();
    const first = await runCli(['keygen'], dir);

    expect(first.code).toBe(0);
    const gitignore = await readFile(join(dir, '.gitignore'), 'utf8');
    expect(gitignore).toContain('*.secret.pqc');

    // A second run must not append the patterns again (idempotent).
    await runCli(['keygen', '--name', 'second'], dir);
    const after = await readFile(join(dir, '.gitignore'), 'utf8');
    expect(after.match(/\*\.secret\.pqc/g)).toHaveLength(1);
  });
});

describe('pqc audit', () => {
  it('clean project: exit 0 and a clear message', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'clean' }));
    await writeFile(join(dir, 'index.js'), 'console.log("no crypto");\n');

    const result = await runCli(['audit'], dir);

    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(/no pre-quantum crypto/i);
  });

  it('detects pre-quantum dependencies and code with their PQC equivalent', async () => {
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

  it('ignores node_modules and dist', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'clean' }));
    await mkdir(join(dir, 'node_modules/lib'), { recursive: true });
    await writeFile(join(dir, 'node_modules/lib/index.js'), "createSign('RSA-SHA256');");

    const result = await runCli(['audit'], dir);

    expect(result.code).toBe(0);
  });

  it('skips files larger than 1 MiB but still scans normal ones', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'mixed' }));
    // Oversized file (> 1 MiB) carrying a known pattern: must be skipped, not flagged.
    const oversized = `createSign('RSA-SHA256');\n${'x'.repeat(1024 * 1024 + 64)}`;
    await writeFile(join(dir, 'huge.js'), oversized);
    // Normal-sized file with a known pattern: must still be detected.
    await writeFile(join(dir, 'small.js'), "createECDH('prime256v1');\n");

    const result = await runCli(['audit'], dir);

    // small.js is detected, so the scan still works and exits non-zero.
    expect(result.code).not.toBe(0);
    expect(result.stdout).toContain('small.js');
    // huge.js is reported as skipped, not as a finding (no `file:line` for it).
    expect(result.stdout).toMatch(/skipped/i);
    expect(result.stdout).toContain('huge.js');
    expect(result.stdout).not.toMatch(/huge\.js:\d+/);
  });
});

describe('encrypt / decrypt', () => {
  it('round-trips a binary file through keygen, encrypt, and decrypt', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    // Binary payload (not UTF-8) so byte fidelity is actually exercised.
    const payload = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256));
    await writeFile(join(dir, 'will.pdf'), payload);

    const enc = await runCli(['encrypt', 'will.pdf', '--key', 'keys/alice.public.pqc'], dir);
    expect(enc.code).toBe(0);
    expect(enc.stdout).toContain('will.pdf.enc');

    // The envelope must not contain the plaintext.
    const envelope = await readFile(join(dir, 'will.pdf.enc'));
    expect(envelope.includes(payload.subarray(0, 64))).toBe(false);

    const dec = await runCli(
      ['decrypt', 'will.pdf.enc', '--key', 'keys/alice.secret.pqc', '--out', 'restored.pdf'],
      dir,
    );
    expect(dec.code).toBe(0);

    const restored = await readFile(join(dir, 'restored.pdf'));
    expect(restored.equals(payload)).toBe(true);
  });

  it('decrypt defaults the output to the input without .enc', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'sealed until the end');
    await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);

    // Default decrypt target is note.txt, which still exists: refuse first…
    const refused = await runCli(
      ['decrypt', 'note.txt.enc', '--key', 'keys/alice.secret.pqc'],
      dir,
    );
    expect(refused.code).not.toBe(0);
    expect(refused.stderr + refused.stdout).toContain('--force');

    // …and overwrite with --force.
    const forced = await runCli(
      ['decrypt', 'note.txt.enc', '--key', 'keys/alice.secret.pqc', '--force'],
      dir,
    );
    expect(forced.code).toBe(0);
    expect((await readFile(join(dir, 'note.txt'), 'utf8')).toString()).toBe('sealed until the end');
  });

  it.skipIf(process.platform === 'win32')(
    'warns when the secret key file is group- or other-readable',
    async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      await writeFile(join(dir, 'note.txt'), 'quiet');
      await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);
      await chmod(join(dir, 'keys/alice.secret.pqc'), 0o644);

      const result = await runCli(
        ['decrypt', 'note.txt.enc', '--key', 'keys/alice.secret.pqc', '--out', 'other.txt'],
        dir,
      );

      // A warning, not a refusal: the decryption still succeeds.
      expect(result.code).toBe(0);
      expect(result.stdout + result.stderr).toMatch(/0644 .* too open/);
      expect(result.stdout + result.stderr).toContain('chmod 600');
    },
  );

  it.skipIf(process.platform === 'win32')(
    'does not warn about permissions of the public key on encrypt',
    async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      await writeFile(join(dir, 'note.txt'), 'quiet');

      const result = await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);

      expect(result.code).toBe(0);
      expect(result.stdout + result.stderr).not.toMatch(/too open/);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'writes the recovered plaintext readable only by its owner (0600)',
    async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      await writeFile(join(dir, 'note.txt'), 'owner eyes only');
      await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);

      // Pre-create the output with wide permissions: --force must not keep them.
      await writeFile(join(dir, 'restored.txt'), 'stale', { mode: 0o644 });
      const result = await runCli(
        [
          'decrypt',
          'note.txt.enc',
          '--key',
          'keys/alice.secret.pqc',
          '--out',
          'restored.txt',
          '--force',
        ],
        dir,
      );

      expect(result.code).toBe(0);
      expect((await stat(join(dir, 'restored.txt'))).mode & 0o777).toBe(0o600);
      expect(await readFile(join(dir, 'restored.txt'), 'utf8')).toBe('owner eyes only');
    },
  );

  it('decrypt fails cleanly with the wrong secret key', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await runCli(['keygen', '--name', 'mallory'], dir);
    await writeFile(join(dir, 'note.txt'), 'for alice only');
    await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);

    const result = await runCli(
      ['decrypt', 'note.txt.enc', '--key', 'keys/mallory.secret.pqc', '--out', 'leak.txt'],
      dir,
    );

    expect(result.code).not.toBe(0);
    expect(existsSync(join(dir, 'leak.txt'))).toBe(false);
  });

  it('rejects a public key where a secret key is expected', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'x');
    await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);

    const result = await runCli(
      ['decrypt', 'note.txt.enc', '--key', 'keys/alice.public.pqc', '--out', 'other.txt'],
      dir,
    );

    expect(result.code).not.toBe(0);
    expect(result.stderr + result.stdout).toMatch(/secret key/i);
  });

  it('encrypt output interoperates with the SDK (and vice versa)', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    const secretSerialized = (await readFile(join(dir, 'keys/alice.secret.pqc'), 'utf8')).trim();
    const publicSerialized = (await readFile(join(dir, 'keys/alice.public.pqc'), 'utf8')).trim();
    const secretKey = pqc.keys.deserialize(secretSerialized, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const publicKey = pqc.keys.deserialize(publicSerialized, {
      algorithm: 'ml-kem-768',
      use: 'public',
    });

    // CLI encrypt -> SDK decrypt
    await writeFile(join(dir, 'a.txt'), 'from the CLI');
    await runCli(['encrypt', 'a.txt', '--key', 'keys/alice.public.pqc'], dir);
    const cliEnvelope = await readFile(join(dir, 'a.txt.enc'));
    const sdkPlain = await pqc.decrypt(new Uint8Array(cliEnvelope), secretKey);
    expect(Buffer.from(sdkPlain).toString()).toBe('from the CLI');

    // SDK encrypt -> CLI decrypt
    const sdkEnvelope = await pqc.encrypt('from the SDK', publicKey);
    await writeFile(join(dir, 'b.enc'), sdkEnvelope);
    const result = await runCli(['decrypt', 'b.enc', '--key', 'keys/alice.secret.pqc'], dir);
    expect(result.code).toBe(0);
    expect(await readFile(join(dir, 'b'), 'utf8')).toBe('from the SDK');
  });
});
