/**
 * FileKeyStore: on-disk layout, permissions, persistence across instances,
 * CLI-format compatibility, and rejection of unsafe files and key ids.
 */

import { chmod, mkdir, mkdtemp, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { pqc } from '@pqc-sdk/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FileKeyStore, KeystoreError, defaultKeystoreDir } from './keystore.js';

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
