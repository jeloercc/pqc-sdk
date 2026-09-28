/**
 * FileKeyStore: on-disk layout, permissions, persistence across instances,
 * CLI-format compatibility, and rejection of unsafe files and key ids.
 */

import { chmod, mkdir, mkdtemp, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { pqc } from '@pqc-sdk/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  DEFAULT_MAX_KEYS,
  FileKeyStore,
  KeystoreError,
  type StatLike,
  ancestorDirectoryProblem,
  defaultKeystoreDir,
  directoryChainProblem,
  keystoreDirectoryProblem,
  parseMaxKeys,
  publicFileProblem,
} from './keystore.js';

const POSIX = process.platform !== 'win32';

let root: string;
let dir: string;
let warnings: string[];

function store(): FileKeyStore {
  return new FileKeyStore(dir, { warn: (message) => warnings.push(message) });
}

async function expectKeystoreError(promise: Promise<unknown>, code: string): Promise<void> {
  const error: unknown = await promise.then(
    () => undefined,
    (cause: unknown) => cause,
  );
  expect(error).toBeInstanceOf(KeystoreError);
  expect((error as KeystoreError).code).toBe(code);
}

/** Writes a key pair exactly as `pqc keygen` does (packages/cli/src/keyfiles.ts). */
async function writeCliKeyPair(name: string, algorithm: 'x-wing' | 'ml-dsa-65'): Promise<void> {
  const pair = await pqc.keys.generate({ algorithm });
  await writeFile(join(dir, `${name}.public.pqc`), `${pqc.keys.serialize(pair.publicKey)}\n`);
  const secretPath = join(dir, `${name}.secret.pqc`);
  await writeFile(secretPath, `${pqc.keys.serialize(pair.secretKey)}\n`, { mode: 0o600 });
  await chmod(secretPath, 0o600);
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'pqc-mcp-keystore-'));
  dir = join(root, 'keys');
  warnings = [];
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('generate', () => {
  it.skipIf(!POSIX)('creates the directory 0700 and both files 0600', async () => {
    const info = await store().generate('x-wing');
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    for (const suffix of ['.public.pqc', '.secret.pqc']) {
      expect((await stat(join(dir, `${info.keyId}${suffix}`))).mode & 0o777).toBe(0o600);
    }
  });

  it('writes the CLI format and leaves no temp files behind', async () => {
    const info = await store().generate('ml-kem-768');
    expect(info.keyId).toMatch(/^ml-kem-768-[0-9a-f]{12}$/);
    expect((await readdir(dir)).sort()).toEqual(
      [`${info.keyId}.public.pqc`, `${info.keyId}.secret.pqc`].sort(),
    );
  });

  it('writes nothing for an unsupported algorithm', async () => {
    await expect(store().generate('ml-kem-9999' as never)).rejects.toMatchObject({
      code: 'UNSUPPORTED_ALGORITHM',
    });
    await expect(stat(dir)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('persistence', () => {
  it('a fresh instance on the same directory lists and loads earlier keys', async () => {
    const info = await store().generate('x-wing');
    const ciphertext = await pqc.encrypt(
      'survives a restart',
      pqc.keys.deserialize(info.publicToken) as never,
    );

    const restarted = store();
    expect(await restarted.list()).toEqual([info]);
    const secretKey = await restarted.loadSecretKey(info.keyId);
    const plaintext = await pqc.decrypt(ciphertext, secretKey as never);
    expect(new TextDecoder().decode(plaintext)).toBe('survives a restart');
  });

  it('loads key pairs written by the CLI without going through the model', async () => {
    await mkdir(dir, { mode: 0o700 });
    await writeCliKeyPair('alice', 'x-wing');
    await writeCliKeyPair('signer_1', 'ml-dsa-65');
    const keys = await store().list();
    expect(keys.map((key) => [key.keyId, key.algorithm])).toEqual([
      ['alice', 'x-wing'],
      ['signer_1', 'ml-dsa-65'],
    ]);
    expect((await store().loadSecretKey('alice')).use).toBe('secret');
  });
});

describe('list', () => {
  it('returns an empty list when the directory does not exist yet', async () => {
    expect(await store().list()).toEqual([]);
  });

  it('ignores CLI names the keystore does not accept, warning once per file', async () => {
    await mkdir(dir, { mode: 0o700 });
    await writeCliKeyPair('alice.work', 'x-wing');
    await writeCliKeyPair('bob', 'x-wing');
    const keystore = store();
    expect((await keystore.list()).map((key) => key.keyId)).toEqual(['bob']);
    expect((await keystore.list()).map((key) => key.keyId)).toEqual(['bob']);
    // Two files (public + secret) share the invalid name; each warns exactly once.
    expect(warnings.filter((w) => w.includes('alice.work'))).toHaveLength(2);
  });

  it('skips a public key without a matching secret key', async () => {
    await mkdir(dir, { mode: 0o700 });
    await writeCliKeyPair('orphan', 'x-wing');
    await rm(join(dir, 'orphan.secret.pqc'));
    expect(await store().list()).toEqual([]);
    expect(warnings).toHaveLength(1);
  });
});

describe('loadSecretKey', () => {
  it('reports an unknown key id as KEY_NOT_FOUND', async () => {
    await store().generate('x-wing');
    await expectKeystoreError(store().loadSecretKey('nobody'), 'KEY_NOT_FOUND');
  });

  it.each(['../outside', 'a/b', 'a\\b', 'alice.work', '', '-leading-dash', 'x'.repeat(65)])(
    'rejects key id %j before touching the filesystem',
    async (keyId) => {
      // A valid secret key sits one level up: a traversal would find it.
      await writeCliKeyPairAt(root, 'outside');
      await expectKeystoreError(store().loadSecretKey(keyId), 'INVALID_ARGUMENT');
    },
  );

  it.skipIf(!POSIX)('refuses a secret key file readable by group or others', async () => {
    const info = await store().generate('x-wing');
    await chmod(join(dir, `${info.keyId}.secret.pqc`), 0o644);
    await expectKeystoreError(store().loadSecretKey(info.keyId), 'KEYSTORE_INSECURE');
  });

  it.skipIf(!POSIX)('refuses a secret key file that is a symlink', async () => {
    const info = await store().generate('x-wing');
    const target = join(root, 'elsewhere.secret.pqc');
    await rm(join(dir, `${info.keyId}.secret.pqc`));
    await writeFile(target, 'unused', { mode: 0o600 });
    await symlink(target, join(dir, `${info.keyId}.secret.pqc`));
    await expectKeystoreError(store().loadSecretKey(info.keyId), 'KEYSTORE_INSECURE');
  });

  it.skipIf(!POSIX)('refuses a keystore directory writable by group or others', async () => {
    const info = await store().generate('x-wing');
    await chmod(dir, 0o770);
    await expectKeystoreError(store().loadSecretKey(info.keyId), 'KEYSTORE_INSECURE');
    await expectKeystoreError(store().list(), 'KEYSTORE_INSECURE');
  });

  it.skipIf(!POSIX)(
    'accepts a directory readable by others (e.g. created by the CLI)',
    async () => {
      const info = await store().generate('x-wing');
      await chmod(dir, 0o755);
      expect((await store().loadSecretKey(info.keyId)).use).toBe('secret');
    },
  );

  it('reports a malformed or public-only secret file as INVALID_KEY_FILE', async () => {
    const info = await store().generate('x-wing');
    const secretPath = join(dir, `${info.keyId}.secret.pqc`);
    await writeFile(secretPath, 'not a key\n', { mode: 0o600 });
    await expectKeystoreError(store().loadSecretKey(info.keyId), 'INVALID_KEY_FILE');
    await writeFile(secretPath, `${info.publicToken}\n`, { mode: 0o600 });
    await expectKeystoreError(store().loadSecretKey(info.keyId), 'INVALID_KEY_FILE');
  });

  it('never puts key material or paths in error messages', async () => {
    const info = await store().generate('x-wing');
    const secretPath = join(dir, `${info.keyId}.secret.pqc`);
    await writeFile(secretPath, 'pqcv1.x-wing.secret.AAAA\n', { mode: 0o600 });
    const error: unknown = await store()
      .loadSecretKey(info.keyId)
      .then(
        () => undefined,
        (cause: unknown) => cause,
      );
    if (!(error instanceof KeystoreError)) throw new Error('expected a KeystoreError');
    expect(error.message).not.toContain('pqcv1');
    expect(error.message).not.toContain(root);
  });
});

describe('fromEnv', () => {
  it('uses PQC_KEYSTORE_DIR when set', () => {
    expect(FileKeyStore.fromEnv({ PQC_KEYSTORE_DIR: dir }).directory).toBe(dir);
  });

  it('falls back to a dedicated per-user directory, never ./keys', () => {
    const fallback = FileKeyStore.fromEnv({}).directory;
    expect(fallback).toBe(defaultKeystoreDir({}));
    expect(fallback).toMatch(/pqc-sdk[\\/]agent-keys$/);
    expect(fallback).not.toBe(join(process.cwd(), 'keys'));
  });
});

async function writeCliKeyPairAt(directory: string, name: string): Promise<void> {
  const pair = await pqc.keys.generate({ algorithm: 'x-wing' });
  await writeFile(join(directory, `${name}.public.pqc`), `${pqc.keys.serialize(pair.publicKey)}\n`);
  await writeFile(
    join(directory, `${name}.secret.pqc`),
    `${pqc.keys.serialize(pair.secretKey)}\n`,
    {
      mode: 0o600,
    },
  );
}

// ─── O2: key cap ──────────────────────────────────────────────────────────────

describe('key cap (PQC_MCP_MAX_KEYS)', () => {
  function capped(maxKeys: number): FileKeyStore {
    return new FileKeyStore(dir, { warn: (message) => warnings.push(message), maxKeys });
  }

  it('refuses to generate beyond the cap with KEYSTORE_FULL', async () => {
    const keystore = capped(2);
    await keystore.generate('x-wing');
    await keystore.generate('x-wing');
    await expectKeystoreError(keystore.generate('x-wing'), 'KEYSTORE_FULL');
    expect(await keystore.list()).toHaveLength(2);
  });

  it('counts keys imported with the CLI', async () => {
    await mkdir(dir, { mode: 0o700 });
    await writeCliKeyPair('imported', 'x-wing');
    await expectKeystoreError(capped(1).generate('x-wing'), 'KEYSTORE_FULL');
  });

  it('frees a slot when a key is removed', async () => {
    const keystore = capped(1);
    const info = await keystore.generate('x-wing');
    await expectKeystoreError(keystore.generate('x-wing'), 'KEYSTORE_FULL');
    await rm(join(dir, `${info.keyId}.secret.pqc`));
    await rm(join(dir, `${info.keyId}.public.pqc`));
    await expect(keystore.generate('x-wing')).resolves.toMatchObject({ algorithm: 'x-wing' });
  });

  it('holds under concurrent generate calls', async () => {
    const keystore = capped(2);
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () => keystore.generate('x-wing')),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
    for (const r of results.filter((r) => r.status === 'rejected')) {
      expect((r.reason as KeystoreError).code).toBe('KEYSTORE_FULL');
    }
    expect((await readdir(dir)).filter((n) => n.endsWith('.secret.pqc'))).toHaveLength(2);
  });

  it('parses PQC_MCP_MAX_KEYS strictly', () => {
    expect(parseMaxKeys(undefined)).toBe(DEFAULT_MAX_KEYS);
    expect(parseMaxKeys('')).toBe(DEFAULT_MAX_KEYS);
    expect(parseMaxKeys('7')).toBe(7);
    for (const bad of ['0', '-1', '1.5', 'abc', '07', ' 5', '1e3']) {
      expect(() => parseMaxKeys(bad)).toThrow(/PQC_MCP_MAX_KEYS must be a positive integer/);
    }
    expect(FileKeyStore.fromEnv({ PQC_KEYSTORE_DIR: dir, PQC_MCP_MAX_KEYS: '3' }).maxKeys).toBe(3);
    expect(() =>
      FileKeyStore.fromEnv({ PQC_KEYSTORE_DIR: dir, PQC_MCP_MAX_KEYS: 'abc' }),
    ).toThrow();
  });

  it('defaults to 100 keys', () => {
    expect(store().maxKeys).toBe(100);
  });
});

// ─── O3: directory, ancestor and public-file checks ──────────────────────────

describe('permission policy (synthetic stats)', () => {
  const ME = 501;
  const OTHER = 777;
  const dirStat = (mode: number, uid: number): StatLike => ({ mode: 0o040000 | mode, uid });

  it('requires the keystore directory to be owned by the server user', () => {
    expect(keystoreDirectoryProblem(dirStat(0o700, ME), ME)).toBeUndefined();
    expect(keystoreDirectoryProblem(dirStat(0o700, OTHER), ME)).toMatch(/not owned/);
    expect(keystoreDirectoryProblem(dirStat(0o770, ME), ME)).toMatch(/writable/);
  });

  it('accepts root- or self-owned ancestors, sticky ones even if world-writable', () => {
    expect(ancestorDirectoryProblem(dirStat(0o755, 0), ME)).toBeUndefined();
    expect(ancestorDirectoryProblem(dirStat(0o700, ME), ME)).toBeUndefined();
    expect(ancestorDirectoryProblem(dirStat(0o1777, 0), ME)).toBeUndefined();
    expect(ancestorDirectoryProblem(dirStat(0o777, 0), ME)).toMatch(/writable/);
    expect(ancestorDirectoryProblem(dirStat(0o775, ME), ME)).toMatch(/writable/);
    expect(ancestorDirectoryProblem(dirStat(0o755, OTHER), ME)).toMatch(/another user/);
  });

  it('refuses a keystore under a 1777 parent when another user created it first', () => {
    // In a sticky directory another user can create our keystore path before
    // the server does. The sticky exception must not let that through: the
    // keystore directory itself has to belong to the server's user.
    const sticky = { path: '/tmp', ...dirStat(0o1777, 0) };
    const root = { path: '/', ...dirStat(0o755, 0) };
    expect(directoryChainProblem(dirStat(0o700, OTHER), [sticky, root], ME)).toEqual({
      problem: "the keystore directory is not owned by the server's user",
    });
    expect(directoryChainProblem(dirStat(0o700, ME), [sticky, root], ME)).toBeUndefined();
  });

  it('reports the first offending ancestor with its path', () => {
    const chain = [
      { path: '/home/me', ...dirStat(0o775, ME) },
      { path: '/home', ...dirStat(0o755, 0) },
    ];
    expect(directoryChainProblem(dirStat(0o700, ME), chain, ME)).toEqual({
      path: '/home/me',
      problem: 'a parent directory of the keystore is writable by group or others (and not sticky)',
    });
  });

  it('requires public files to be owned by the server user and not writable by others', () => {
    const file = (mode: number, uid: number): StatLike => ({ mode: 0o100000 | mode, uid });
    expect(publicFileProblem(file(0o644, ME), ME)).toBeUndefined();
    expect(publicFileProblem(file(0o600, OTHER), ME)).toMatch(/not owned/);
    expect(publicFileProblem(file(0o664, ME), ME)).toMatch(/writable/);
  });
});

describe('directory checks (real filesystem)', () => {
  it.skipIf(!POSIX)(
    'refuses a keystore under a group-writable parent, naming it only in the log',
    async () => {
      const parent = join(root, 'shared');
      await mkdir(parent);
      await chmod(parent, 0o775);
      dir = join(parent, 'keys');
      const error = await store()
        .generate('x-wing')
        .then(
          () => undefined,
          (cause: unknown) => cause,
        );
      expect(error).toBeInstanceOf(KeystoreError);
      expect((error as KeystoreError).code).toBe('KEYSTORE_INSECURE');
      expect((error as KeystoreError).message).not.toContain(root);
      expect(warnings.some((w) => w.includes(parent))).toBe(true);
    },
  );

  it.skipIf(!POSIX)('accepts a keystore under a sticky world-writable parent it owns', async () => {
    const parent = join(root, 'sticky');
    await mkdir(parent);
    await chmod(parent, 0o1777);
    dir = join(parent, 'keys');
    const info = await store().generate('x-wing');
    expect((await store().loadSecretKey(info.keyId)).use).toBe('secret');
  });

  it.skipIf(!POSIX)('refuses a keystore path that is a symlink', async () => {
    const info = await store().generate('x-wing');
    const alias = join(root, 'alias');
    await symlink(dir, alias, 'dir');
    const aliased = new FileKeyStore(alias, { warn: (m) => warnings.push(m) });
    await expectKeystoreError(aliased.list(), 'KEYSTORE_INSECURE');
    await expectKeystoreError(aliased.loadSecretKey(info.keyId), 'KEYSTORE_INSECURE');
  });

  it.skipIf(!POSIX)(
    'skips a group-writable public key file with a warning, still listing the rest',
    async () => {
      const planted = await store().generate('x-wing');
      const fine = await store().generate('x-wing');
      await chmod(join(dir, `${planted.keyId}.public.pqc`), 0o664);
      expect((await store().list()).map((k) => k.keyId)).toEqual([fine.keyId]);
      expect(warnings.some((w) => w.includes(planted.keyId) && w.includes('writable'))).toBe(true);
    },
  );

  it.skipIf(!POSIX)('skips a public key file that is a symlink', async () => {
    const info = await store().generate('x-wing');
    const publicPath = join(dir, `${info.keyId}.public.pqc`);
    const target = join(root, 'elsewhere.public.pqc');
    await writeFile(target, `${info.publicToken}\n`, { mode: 0o600 });
    await rm(publicPath);
    await symlink(target, publicPath);
    expect(await store().list()).toEqual([]);
    expect(warnings.some((w) => w.includes('symlink'))).toBe(true);
  });
});

// ─── O4: orphaned secret files ───────────────────────────────────────────────

class FailingPublicWrite extends FileKeyStore {
  protected override async writeExclusive(path: string, contents: string): Promise<void> {
    if (path.endsWith('.public.pqc')) throw new Error('simulated disk full');
    return super.writeExclusive(path, contents);
  }
}

describe('orphaned secret files', () => {
  it('removes the secret file when writing its public file fails', async () => {
    const failing = new FailingPublicWrite(dir, { warn: (m) => warnings.push(m) });
    await expect(failing.generate('x-wing')).rejects.toThrow('simulated disk full');
    expect(await readdir(dir)).toEqual([]);
  });

  it('warns once about a secret file without a public file', async () => {
    const info = await store().generate('x-wing');
    await rm(join(dir, `${info.keyId}.public.pqc`));
    const keystore = store();
    expect(await keystore.list()).toEqual([]);
    expect(await keystore.list()).toEqual([]);
    expect(
      warnings.filter((w) => w.includes(info.keyId) && w.includes('no public key file')),
    ).toHaveLength(1);
  });
});
