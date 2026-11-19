import { link, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { pipeToOutput, writeOutput } from '../src/output.js';

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, link: vi.fn(actual.link) };
});

const directories: string[] = [];

async function freshDir(base = tmpdir()): Promise<string> {
  const dir = await mkdtemp(join(base, '.pqc-output-test-'));
  directories.push(dir);
  return dir;
}

afterEach(async () => {
  vi.mocked(link).mockReset();
  vi.mocked(link).mockImplementation(
    (await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises')).link,
  );
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('secure output', () => {
  it('publishes ciphertext on the repository filesystem without requiring hard links', async () => {
    const dir = await freshDir(process.cwd());
    const path = join(dir, 'ciphertext.enc');
    const streamedPath = join(dir, 'streamed.enc');
    try {
      await writeOutput(path, new TextEncoder().encode('ciphertext'), { force: false });
      expect(await readFile(path, 'utf8')).toBe('ciphertext');
      await expect(
        writeOutput(path, new TextEncoder().encode('replacement'), { force: false }),
      ).rejects.toThrow('already exists');
      expect(await readFile(path, 'utf8')).toBe('ciphertext');

      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('streamed ciphertext'));
          controller.close();
        },
      });
      await pipeToOutput(source, streamedPath, { force: false });
      expect(await readFile(streamedPath, 'utf8')).toBe('streamed ciphertext');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('never publishes private output unless the filesystem enforces mode 0600', async () => {
    const dir = await freshDir(process.cwd());
    const path = join(dir, 'plaintext');
    try {
      try {
        await writeOutput(path, new TextEncoder().encode('secret'), {
          force: false,
          mode: 0o600,
        });
        expect((await stat(path)).mode & 0o777).toBe(0o600);
      } catch (error) {
        expect(String(error)).toContain('Cannot enforce private output permissions');
        await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform === 'win32')('publishes private output with mode 0600', async () => {
    const dir = await freshDir();
    const path = join(dir, 'output');
    await writeOutput(path, new TextEncoder().encode('test data'), { force: false, mode: 0o600 });
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });
  it('refuses a symlink even with force and leaves its target untouched', async () => {
    const dir = await freshDir();
    const target = join(dir, 'target');
    const path = join(dir, 'output');
    await writeFile(target, 'original');
    await symlink(target, path);
    await expect(
      writeOutput(path, new TextEncoder().encode('replacement'), { force: true }),
    ).rejects.toThrow();
    expect(await readFile(target, 'utf8')).toBe('original');
  });

  it('preserves an existing output when a forced stream fails', async () => {
    const dir = await freshDir();
    const path = join(dir, 'output');
    await writeFile(path, 'original');
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('partial'));
        controller.error(new Error('bad ciphertext'));
      },
    });
    await expect(pipeToOutput(source, path, { force: true })).rejects.toThrow();
    expect(await readFile(path, 'utf8')).toBe('original');
  });
});

describe.each(['ENOTSUP', 'EOPNOTSUPP'])('unsupported hard links (%s)', (code) => {
  it('publishes complete buffered and streaming public output through exclusive copy', async () => {
    const dir = await freshDir();
    vi.mocked(link).mockRejectedValue(Object.assign(new Error('Unsupported hard link'), { code }));
    await writeOutput(join(dir, 'buffered'), new TextEncoder().encode('buffered data'), {
      force: false,
    });
    await pipeToOutput(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('streamed data'));
          controller.close();
        },
      }),
      join(dir, 'streamed'),
      { force: false },
    );
    expect(await readFile(join(dir, 'buffered'), 'utf8')).toBe('buffered data');
    expect(await readFile(join(dir, 'streamed'), 'utf8')).toBe('streamed data');
    expect((await readdir(dir)).sort()).toEqual(['buffered', 'streamed']);
    expect(link).toHaveBeenCalledTimes(2);
  });

  it('keeps an existing destination and removes temporary output when copy is refused', async () => {
    const dir = await freshDir();
    const path = join(dir, 'existing');
    await writeFile(path, 'original');
    vi.mocked(link).mockRejectedValueOnce(
      Object.assign(new Error('Unsupported hard link'), { code }),
    );
    await expect(
      writeOutput(path, new TextEncoder().encode('replacement'), { force: false }),
    ).rejects.toThrow('already exists');
    expect(await readFile(path, 'utf8')).toBe('original');
    expect(await readdir(dir)).toEqual(['existing']);
  });

  it.skipIf(process.platform === 'win32')(
    'refuses the copy fallback for private output',
    async () => {
      const dir = await freshDir();
      vi.mocked(link).mockRejectedValueOnce(
        Object.assign(new Error('Unsupported hard link'), { code }),
      );
      await expect(
        writeOutput(join(dir, 'private'), new TextEncoder().encode('synthetic data'), {
          force: false,
          mode: 0o600,
        }),
      ).rejects.toMatchObject({ code });
      expect(await readdir(dir)).toEqual([]);
    },
  );
});

describe('key pair output', () => {
  it('does not replace an existing secret when the public destination is a symlink', async () => {
    const { writeKeyPair } = await import('../src/keyfiles.js');
    const dir = await freshDir();
    const secret = join(dir, 'key.secret.pqc');
    const target = join(dir, 'target');
    await writeFile(secret, 'original secret');
    await writeFile(target, 'original target');
    await symlink(target, join(dir, 'key.public.pqc'));
    await expect(writeKeyPair(dir, 'key', 'x-wing', true)).rejects.toThrow();
    expect(await readFile(secret, 'utf8')).toBe('original secret');
    expect(await readFile(target, 'utf8')).toBe('original target');
  });
});
