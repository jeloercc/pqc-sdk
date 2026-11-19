import { randomBytes } from 'node:crypto';
import { constants, createWriteStream } from 'node:fs';
import { copyFile, link, lstat, open, rename, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { Writable } from 'node:stream';

import { UsageError } from './errors.js';

async function publishOutput(
  path: string,
  options: { force: boolean; mode?: number },
  write: (handle: FileHandle) => Promise<void>,
): Promise<void> {
  const temp = join(
    dirname(path),
    `.${basename(path)}.pqc-output-${randomBytes(16).toString('hex')}.tmp`,
  );
  // Reserve a private file before writing, even when the final output is public.
  const handle = await open(temp, 'wx', 0o600);
  try {
    if (options.mode !== undefined) {
      await handle.chmod(options.mode);
      if (process.platform !== 'win32') {
        const actualMode = (await handle.stat()).mode & 0o777;
        if (actualMode !== options.mode) {
          throw new UsageError(
            `Cannot enforce private output permissions on this filesystem. Choose a destination that supports mode ${options.mode.toString(8).padStart(4, '0')}.`,
          );
        }
      }
    }
    await write(handle);
    await handle.close();
    if (options.force) {
      try {
        if ((await lstat(path)).isSymbolicLink()) {
          throw new UsageError(`${path} is a symbolic link; refusing to overwrite it.`);
        }
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause;
      }
      // rename replaces a directory entry, so even a symlink swapped in after
      // lstat is never followed.
      await rename(temp, path);
    } else {
      try {
        await link(temp, path);
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new UsageError(`${path} already exists. Use --force to overwrite it.`);
        }
        const code = (cause as NodeJS.ErrnoException).code;
        if (options.mode !== undefined || (code !== 'ENOTSUP' && code !== 'EOPNOTSUPP')) {
          throw cause;
        }
        // exFAT and some network filesystems do not support hard links. These
        // outputs are non-sensitive (private outputs require verified POSIX
        // permissions above), so copy the completed temporary file using the
        // filesystem's exclusive-create primitive instead of following or
        // overwriting an existing destination.
        try {
          await copyFile(temp, path, constants.COPYFILE_EXCL);
        } catch (copyCause) {
          if ((copyCause as NodeJS.ErrnoException).code === 'EEXIST') {
            throw new UsageError(`${path} already exists. Use --force to overwrite it.`);
          }
          // copyFile may leave a partial destination after an I/O error.
          await unlink(path).catch(() => undefined);
          throw copyCause;
        }
      }
    }
  } finally {
    await handle.close().catch(() => undefined);
    await unlink(temp).catch(() => undefined);
  }
}

/**
 * Write to a private temporary file and publish only after the write succeeds.
 *
 * @example
 * ```ts
 * import { writeOutput } from './output.js';
 * await writeOutput('recovered.txt', plaintext, { force: false, mode: 0o600 });
 * ```
 */
export async function writeOutput(
  path: string,
  data: Uint8Array,
  options: { force: boolean; mode?: number },
): Promise<void> {
  await publishOutput(path, options, async (handle) => {
    await handle.writeFile(data);
  });
}

/**
 * Publish streaming output only after the complete stream succeeds.
 *
 * @example
 * ```ts
 * import { pipeToOutput } from './output.js';
 * await pipeToOutput(ciphertextStream, 'message.enc', { force: false });
 * ```
 */
export async function pipeToOutput(
  source: ReadableStream<Uint8Array>,
  path: string,
  options: { force: boolean; mode?: number },
): Promise<void> {
  await publishOutput(path, options, async (handle) => {
    const stream = createWriteStream('', { fd: handle.fd, autoClose: false });
    await source.pipeTo(Writable.toWeb(stream) as WritableStream<Uint8Array>);
  });
}
