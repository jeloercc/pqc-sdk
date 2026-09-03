import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdtemp, mkdir, readFile, stat, truncate, writeFile } from 'node:fs/promises';
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
    expect(config.defaultAlgorithm).toBe('x-wing');

    const publicKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.public.pqc'), 'utf8')).trim(),
    );
    const secretKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/dev.secret.pqc'), 'utf8')).trim(),
    );
    expect(publicKey.algorithm).toBe('x-wing');
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
  it('generates the x-wing hybrid in ./keys by default', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/x-wing.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('x-wing');
    await readFile(join(dir, 'keys/x-wing.secret.pqc'), 'utf8');
  });

  it('still generates pure ML-KEM-768 on request, with its own file names', async () => {
    // The CLI half of the 0.8.0 migration path (docs/MIGRATION-0.8.md).
    const dir = await freshDir();
    const result = await runCli(['keygen', '--algorithm', 'ml-kem-768'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/ml-kem-768.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('ml-kem-768');
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

  it('generates an x-wing pair (1216-byte public, 32-byte secret seed)', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen', '--algorithm', 'x-wing'], dir);

    expect(result.code).toBe(0);
    const publicKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/x-wing.public.pqc'), 'utf8')).trim(),
    );
    const secretKey = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/x-wing.secret.pqc'), 'utf8')).trim(),
    );
    expect(publicKey.algorithm).toBe('x-wing');
    expect(publicKey.bytes.length).toBe(1216);
    expect(secretKey.bytes.length).toBe(32);
  });

  it('honors --name as the base file name (overriding the algorithm default)', async () => {
    const dir = await freshDir();
    const result = await runCli(['keygen', '--name', 'payments'], dir);

    expect(result.code).toBe(0);
    const key = pqc.keys.deserialize(
      (await readFile(join(dir, 'keys/payments.public.pqc'), 'utf8')).trim(),
    );
    expect(key.algorithm).toBe('x-wing');
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
    const original = await readFile(join(dir, 'keys/x-wing.public.pqc'), 'utf8');

    const second = await runCli(['keygen'], dir);
    expect(second.code).not.toBe(0);
    expect(await readFile(join(dir, 'keys/x-wing.public.pqc'), 'utf8')).toBe(original);

    const forced = await runCli(['keygen', '--force'], dir);
    expect(forced.code).toBe(0);
    expect(await readFile(join(dir, 'keys/x-wing.public.pqc'), 'utf8')).not.toBe(original);
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

  it('states its limits: non-exhaustive, and a clean run is not a clean bill of health', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'clean' }));
    await writeFile(join(dir, 'index.js'), 'console.log("no crypto");\n');

    const result = await runCli(['audit'], dir);

    expect(result.stdout).toMatch(/non-exhaustive/i);
    expect(result.stdout).toMatch(/starting point for a migration review/i);
    // The dangerous reading of a clean run is "we have no pre-quantum crypto".
    // The output must actively deny that, not merely omit the claim.
    expect(result.stdout).toMatch(/not a clean bill of health/i);
  });

  it('frames findings as candidates to review, not a finished migration list', async () => {
    const dir = await freshDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'legacy', dependencies: { jsonwebtoken: '^9.0.0' } }),
    );

    const result = await runCli(['audit'], dir);

    expect(result.code).not.toBe(0);
    expect(result.stdout).toMatch(/candidate usage/i);
    expect(result.stdout).toMatch(/confirm each one is genuinely reachable/i);
  });

  it('carries the heuristic caveat in its help text', async () => {
    const dir = await freshDir();
    const result = await runCli(['audit', '--help'], dir);

    expect(result.stdout).toMatch(/non-exhaustive/i);
    expect(result.stdout).toMatch(/not a substitute/i);
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

  it('prints expected errors as one clean line on stderr, without a stack trace', async () => {
    const dir = await freshDir();

    const missing = await runCli(['decrypt', 'missing.enc', '--key', 'nokey.pqc'], dir);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain('Input file not found: missing.enc');
    // No stack frames for user-correctable errors (that would be finding F2).
    expect(missing.stdout + missing.stderr).not.toMatch(/^\s+at /m);

    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'x');
    await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);
    const exists = await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);
    expect(exists.code).toBe(1);
    expect(exists.stderr).toContain('note.txt.enc already exists. Use --force to overwrite it.');
    expect(exists.stdout + exists.stderr).not.toMatch(/^\s+at /m);
  });

  it('reports a missing input before a missing --force on the output', async () => {
    const dir = await freshDir();
    // Input nothere.enc does not exist AND its default output (nothere)
    // already exists: the input error must win.
    await writeFile(join(dir, 'nothere'), 'existing default decrypt target');

    const result = await runCli(['decrypt', 'nothere.enc', '--key', 'nokey.pqc'], dir);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Input file not found');
    expect(result.stderr).not.toContain('already exists');
  });

  it('refuses inputs above the 1 TiB operational ceiling with a clear error', async () => {
    const dir = await freshDir();
    // A sparse file: instant to create, stat.size is what the guard checks.
    await writeFile(join(dir, 'huge.bin'), '');
    await truncate(join(dir, 'huge.bin'), 1024 * 1024 * 1024 * 1024 + 1);

    const enc = await runCli(['encrypt', 'huge.bin', '--key', 'nokey.pqc'], dir);
    expect(enc.code).toBe(1);
    expect(enc.stderr).toMatch(/1 TiB operational limit/);
    expect(enc.stdout + enc.stderr).not.toMatch(/^\s+at /m);

    const dec = await runCli(['decrypt', 'huge.bin', '--key', 'nokey.pqc'], dir);
    expect(dec.code).toBe(1);
    expect(dec.stderr).toMatch(/1 TiB operational limit/);
  });

  it('the operational ceiling error says it is not a cryptographic limit and names the override', async () => {
    const dir = await freshDir();
    await writeFile(join(dir, 'huge.bin'), '');
    await truncate(join(dir, 'huge.bin'), 1024 * 1024 * 1024 * 1024 + 1);

    const enc = await runCli(['encrypt', 'huge.bin', '--key', 'nokey.pqc'], dir);
    expect(enc.code).toBe(1);
    expect(enc.stderr).toContain('not a cryptographic limit');
    expect(enc.stderr).toContain('--max-size');
  });

  it('--max-size raises the operational ceiling and says loudly that the guard was bypassed', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    // Sparse and just past the 1 TiB default: the guard reads stat.size, so
    // this exercises the override without writing a real terabyte. Encryption
    // itself is never reached — readKemKeyFile runs after the size check, and
    // a missing key ends the run before any streaming starts.
    await writeFile(join(dir, 'huge.bin'), '');
    await truncate(join(dir, 'huge.bin'), 1024 * 1024 * 1024 * 1024 + 1);

    const enc = await runCli(
      ['encrypt', 'huge.bin', '--key', 'nokey.pqc', '--max-size', '2TiB'],
      dir,
    );
    // The size guard passed (its refusal message is gone) and the bypass was
    // announced; the run then fails later, on the missing key file.
    expect(enc.stdout).toContain('Operational size guard bypassed');
    expect(enc.stdout).toContain('not against a cryptographic limit');
    expect(enc.stderr).not.toMatch(/operational limit/);

    const dec = await runCli(
      ['decrypt', 'huge.bin', '--key', 'nokey.pqc', '--max-size', '2TiB'],
      dir,
    );
    expect(dec.stdout).toContain('Operational size guard bypassed');
    expect(dec.stderr).not.toMatch(/operational limit/);
  });

  it('--max-size stays silent when it does not actually bypass the default guard', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'small file, well under any ceiling');

    const enc = await runCli(
      ['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc', '--max-size', '2TiB'],
      dir,
    );
    expect(enc.code).toBe(0);
    expect(enc.stdout).not.toContain('Operational size guard bypassed');
  });

  it('--max-size can lower the ceiling, and rejects a malformed value', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'x'.repeat(4096));

    const lowered = await runCli(
      ['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc', '--max-size', '1KiB'],
      dir,
    );
    expect(lowered.code).toBe(1);
    expect(lowered.stderr).toContain('above the 1 KiB operational limit');
    // Lowered below the default, so the message must not advise raising it
    // with the flag the operator just used to lower it.
    expect(lowered.stderr).toContain('Raise --max-size further');

    const bad = await runCli(
      ['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc', '--max-size', 'banana'],
      dir,
    );
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain('Invalid --max-size value');
    expect(bad.stdout + bad.stderr).not.toMatch(/^\s+at /m);
  });

  it('documents --max-size as an operational guard in both help screens', async () => {
    const dir = await freshDir();
    for (const command of ['encrypt', 'decrypt']) {
      const help = await runCli([command, '--help'], dir);
      expect(help.stdout).toContain('--max-size');
      expect(help.stdout).toContain('not a cryptographic limit');
    }
  });

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

  it('decrypt fails closed on a tampered envelope, through the real binary', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--name', 'alice'], dir);
    await writeFile(join(dir, 'note.txt'), 'integrity matters');
    await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);
    const envelope = await readFile(join(dir, 'note.txt.enc'));

    // Sealed payload region: flip one bit of the last byte (inside the GCM tag).
    const sealedTampered = Buffer.from(envelope);
    sealedTampered[sealedTampered.length - 1]! ^= 0x01;
    await writeFile(join(dir, 'sealed.enc'), sealedTampered);
    const sealed = await runCli(
      ['decrypt', 'sealed.enc', '--key', 'keys/alice.secret.pqc', '--out', 'sealed.out'],
      dir,
    );
    expect(sealed.code).toBe(1);
    expect(sealed.stderr).toMatch(/tampered ciphertext or wrong secret key/i);
    expect(sealed.stdout + sealed.stderr).not.toMatch(/^\s+at /m);
    expect(existsSync(join(dir, 'sealed.out'))).toBe(false);

    // Header region: an unknown version byte is rejected before any crypto.
    const headerTampered = Buffer.from(envelope);
    headerTampered[0]! ^= 0xff;
    await writeFile(join(dir, 'header.enc'), headerTampered);
    const header = await runCli(
      ['decrypt', 'header.enc', '--key', 'keys/alice.secret.pqc', '--out', 'header.out'],
      dir,
    );
    expect(header.code).toBe(1);
    expect(header.stderr).toMatch(/unknown header/i);
    expect(existsSync(join(dir, 'header.out'))).toBe(false);

    // KEM ciphertext region: implicit rejection ends in the same clean failure.
    const kemTampered = Buffer.from(envelope);
    kemTampered[2]! ^= 0x01;
    await writeFile(join(dir, 'kem.enc'), kemTampered);
    const kem = await runCli(
      ['decrypt', 'kem.enc', '--key', 'keys/alice.secret.pqc', '--out', 'kem.out'],
      dir,
    );
    expect(kem.code).toBe(1);
    expect(existsSync(join(dir, 'kem.out'))).toBe(false);
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
      algorithm: 'x-wing',
      use: 'secret',
    });
    const publicKey = pqc.keys.deserialize(publicSerialized, {
      algorithm: 'x-wing',
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

  it('rejects a signing (ml-dsa-65) key file with a clear KEM-key error', async () => {
    const dir = await freshDir();
    await runCli(['keygen', '--algorithm', 'ml-dsa-65', '--name', 'signer'], dir);
    await writeFile(join(dir, 'note.txt'), 'x');

    const result = await runCli(['encrypt', 'note.txt', '--key', 'keys/signer.public.pqc'], dir);

    expect(result.code).not.toBe(0);
    expect(result.stderr + result.stdout).toMatch(/ml-dsa-65/i);
    expect(result.stdout + result.stderr).not.toMatch(/^\s+at /m);
  });

  describe('x-wing (pqcenc.v2)', () => {
    it('round-trips a file through keygen --algorithm x-wing, encrypt, and decrypt', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--algorithm', 'x-wing', '--name', 'alice'], dir);
      const payload = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256));
      await writeFile(join(dir, 'will.pdf'), payload);

      const enc = await runCli(['encrypt', 'will.pdf', '--key', 'keys/alice.public.pqc'], dir);
      expect(enc.code).toBe(0);
      // The friendly summary line names the algorithm actually used.
      expect(enc.stdout).toContain('x-wing');

      const dec = await runCli(
        ['decrypt', 'will.pdf.enc', '--key', 'keys/alice.secret.pqc', '--out', 'restored.pdf'],
        dir,
      );
      expect(dec.code).toBe(0);
      expect((await readFile(join(dir, 'restored.pdf'))).equals(payload)).toBe(true);
    });

    it('encrypt output interoperates with the SDK (and vice versa)', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--algorithm', 'x-wing', '--name', 'alice'], dir);
      const secretKey = pqc.keys.deserialize(
        (await readFile(join(dir, 'keys/alice.secret.pqc'), 'utf8')).trim(),
        { algorithm: 'x-wing', use: 'secret' },
      );
      const publicKey = pqc.keys.deserialize(
        (await readFile(join(dir, 'keys/alice.public.pqc'), 'utf8')).trim(),
        { algorithm: 'x-wing', use: 'public' },
      );

      // CLI encrypt -> SDK decrypt
      await writeFile(join(dir, 'a.txt'), 'from the CLI, hybrid');
      await runCli(['encrypt', 'a.txt', '--key', 'keys/alice.public.pqc'], dir);
      const cliEnvelope = await readFile(join(dir, 'a.txt.enc'));
      expect(cliEnvelope[0]).toBe(0x02); // pqcenc.v2 header
      const sdkPlain = await pqc.decrypt(new Uint8Array(cliEnvelope), secretKey);
      expect(Buffer.from(sdkPlain).toString()).toBe('from the CLI, hybrid');

      // SDK encrypt -> CLI decrypt
      const sdkEnvelope = await pqc.encrypt('from the SDK, hybrid', publicKey);
      await writeFile(join(dir, 'b.enc'), sdkEnvelope);
      const result = await runCli(['decrypt', 'b.enc', '--key', 'keys/alice.secret.pqc'], dir);
      expect(result.code).toBe(0);
      expect(await readFile(join(dir, 'b'), 'utf8')).toBe('from the SDK, hybrid');
    });

    it('decrypt fails closed on a tampered v2 envelope, through the real binary', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--algorithm', 'x-wing', '--name', 'alice'], dir);
      await writeFile(join(dir, 'note.txt'), 'integrity matters, hybrid');
      await runCli(['encrypt', 'note.txt', '--key', 'keys/alice.public.pqc'], dir);
      const envelope = await readFile(join(dir, 'note.txt.enc'));

      // Sealed payload region: flip the last byte (inside the GCM tag).
      const sealedTampered = Buffer.from(envelope);
      sealedTampered[sealedTampered.length - 1]! ^= 0x01;
      await writeFile(join(dir, 'sealed.enc'), sealedTampered);
      const sealed = await runCli(
        ['decrypt', 'sealed.enc', '--key', 'keys/alice.secret.pqc', '--out', 'sealed.out'],
        dir,
      );
      expect(sealed.code).toBe(1);
      expect(sealed.stderr).toMatch(/tampered ciphertext or wrong secret key/i);
      expect(existsSync(join(dir, 'sealed.out'))).toBe(false);

      // Header region: an unknown version byte is rejected before any crypto.
      const headerTampered = Buffer.from(envelope);
      headerTampered[0]! ^= 0xff;
      await writeFile(join(dir, 'header.enc'), headerTampered);
      const header = await runCli(
        ['decrypt', 'header.enc', '--key', 'keys/alice.secret.pqc', '--out', 'header.out'],
        dir,
      );
      expect(header.code).toBe(1);
      expect(header.stderr).toMatch(/unknown header/i);
      expect(existsSync(join(dir, 'header.out'))).toBe(false);

      // X-Wing ciphertext region (ct_M): implicit rejection ends in the same
      // clean failure as v1's KEM-ciphertext tamper.
      const ctTampered = Buffer.from(envelope);
      ctTampered[2]! ^= 0x01;
      await writeFile(join(dir, 'ct.enc'), ctTampered);
      const ct = await runCli(
        ['decrypt', 'ct.enc', '--key', 'keys/alice.secret.pqc', '--out', 'ct.out'],
        dir,
      );
      expect(ct.code).toBe(1);
      expect(existsSync(join(dir, 'ct.out'))).toBe(false);
    });

    it('cross-version key confusion fails closed through the real binary', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'kem-alice'], dir);
      await runCli(['keygen', '--algorithm', 'x-wing', '--name', 'xwing-alice'], dir);
      await writeFile(join(dir, 'note.txt'), 'x');

      // v1 envelope decrypted with an x-wing key.
      await runCli(['encrypt', 'note.txt', '--key', 'keys/kem-alice.public.pqc'], dir);
      const v1Wrong = await runCli(
        ['decrypt', 'note.txt.enc', '--key', 'keys/xwing-alice.secret.pqc', '--out', 'v1.out'],
        dir,
      );
      expect(v1Wrong.code).not.toBe(0);
      expect(existsSync(join(dir, 'v1.out'))).toBe(false);

      // v2 envelope decrypted with an ml-kem-768 key.
      await runCli(
        ['encrypt', 'note.txt', '--key', 'keys/xwing-alice.public.pqc', '--out', 'note2.enc'],
        dir,
      );
      const v2Wrong = await runCli(
        ['decrypt', 'note2.enc', '--key', 'keys/kem-alice.secret.pqc', '--out', 'v2.out'],
        dir,
      );
      expect(v2Wrong.code).not.toBe(0);
      expect(existsSync(join(dir, 'v2.out'))).toBe(false);
    });
  });

  describe('streaming (files above the 8 MiB threshold)', () => {
    // Deterministic, non-trivial content — fast to generate, and a real
    // byte-for-byte comparison actually means something (not just zeros).
    function largePayload(bytes: number): Buffer {
      const buf = Buffer.alloc(bytes);
      for (let i = 0; i < bytes; i++) {
        buf[i] = i % 256;
      }
      return buf;
    }

    it.each(['ml-kem-768', 'x-wing'] as const)(
      'streams a file above the threshold and round-trips it byte-for-byte (%s)',
      async (algorithm) => {
        const dir = await freshDir();
        await runCli(['keygen', '--algorithm', algorithm, '--name', 'alice'], dir);
        const payload = largePayload(9 * 1024 * 1024); // 9 MiB, above the 8 MiB threshold
        await writeFile(join(dir, 'large.bin'), payload);

        const enc = await runCli(['encrypt', 'large.bin', '--key', 'keys/alice.public.pqc'], dir);
        expect(enc.code).toBe(0);
        expect(enc.stdout).toContain('streamed');

        // The streaming envelope's leading version byte (docs/serialization-format.md
        // §9.1): 0x03 for ml-kem-768, 0x04 for x-wing — never the one-shot
        // 0x01/0x02, proving the threshold actually routed to the streaming path.
        const envelopeHead = await readFile(join(dir, 'large.bin.enc'));
        expect(envelopeHead[0]).toBe(algorithm === 'ml-kem-768' ? 0x03 : 0x04);

        // --out avoids colliding with the original large.bin still present
        // in dir (decrypt's default output would otherwise be that same
        // path, which already exists).
        const dec = await runCli(
          ['decrypt', 'large.bin.enc', '--key', 'keys/alice.secret.pqc', '--out', 'roundtrip.bin'],
          dir,
        );
        expect(dec.code).toBe(0);
        expect(dec.stdout).toContain('streamed');

        const roundtripped = await readFile(join(dir, 'roundtrip.bin'));
        expect(roundtripped.equals(payload)).toBe(true);
      },
    );

    it('decrypts a small SDK-produced streaming envelope, dispatching on the version byte rather than file size', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      const publicSerialized = (await readFile(join(dir, 'keys/alice.public.pqc'), 'utf8')).trim();
      const publicKey = pqc.keys.deserialize(publicSerialized, {
        algorithm: 'x-wing',
        use: 'public',
      });

      // A tiny plaintext, but produced via encryptStream directly — this is
      // a real streaming envelope (version 0x04 for x-wing) despite being far below
      // the CLI's 8 MiB threshold, exactly the case size-based dispatch on
      // decrypt would get wrong.
      // eslint-disable-next-line @typescript-eslint/require-await
      async function* source() {
        yield new TextEncoder().encode('tiny but streamed');
      }
      const parts: Uint8Array[] = [];
      for await (const chunk of pqc.encryptStream(publicKey, source(), { chunkSize: 8 })) {
        parts.push(chunk);
      }
      const total = parts.reduce((n, p) => n + p.length, 0);
      const envelope = Buffer.concat(
        parts.map((p) => Buffer.from(p)),
        total,
      );
      expect(envelope[0]).toBe(0x04);
      await writeFile(join(dir, 'tiny-streamed.enc'), envelope);

      const result = await runCli(
        ['decrypt', 'tiny-streamed.enc', '--key', 'keys/alice.secret.pqc'],
        dir,
      );
      expect(result.code).toBe(0);
      expect(await readFile(join(dir, 'tiny-streamed'), 'utf8')).toBe('tiny but streamed');
    });

    it('a tampered large ciphertext fails cleanly and leaves no partial output file', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      const payload = largePayload(9 * 1024 * 1024);
      await writeFile(join(dir, 'large.bin'), payload);
      await runCli(['encrypt', 'large.bin', '--key', 'keys/alice.public.pqc'], dir);

      const envelope = await readFile(join(dir, 'large.bin.enc'));
      // Flip a byte deep inside the ciphertext (well past the first chunk),
      // so decryption yields at least one genuine chunk before failing —
      // the exact scenario pipeToOutput's cleanup exists for.
      const tampered = Buffer.from(envelope);
      const midpoint = Math.floor(tampered.length / 2);
      tampered[midpoint] = tampered[midpoint]! ^ 0xff;
      await writeFile(join(dir, 'tampered.enc'), tampered);

      const result = await runCli(
        ['decrypt', 'tampered.enc', '--key', 'keys/alice.secret.pqc', '--out', 'tampered.out'],
        dir,
      );
      expect(result.code).toBe(1);
      expect(result.stdout + result.stderr).not.toMatch(/^\s+at /m);
      // The critical assertion: no partial, unauthenticated plaintext left
      // on disk for the caller to mistake for a (short but valid) result.
      expect(existsSync(join(dir, 'tampered.out'))).toBe(false);
    });

    it('refuses to overwrite an existing output file when streaming, same as the one-shot path', async () => {
      const dir = await freshDir();
      await runCli(['keygen', '--name', 'alice'], dir);
      const payload = largePayload(9 * 1024 * 1024);
      await writeFile(join(dir, 'large.bin'), payload);
      await writeFile(join(dir, 'large.bin.enc'), 'pre-existing, must not be clobbered');

      const result = await runCli(['encrypt', 'large.bin', '--key', 'keys/alice.public.pqc'], dir);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain('large.bin.enc already exists. Use --force to overwrite it.');
      expect(
        (await readFile(join(dir, 'large.bin.enc'), 'utf8')) ===
          'pre-existing, must not be clobbered',
      ).toBe(true);
    });
  });
});
