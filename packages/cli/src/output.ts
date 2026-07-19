import { chmod, writeFile } from 'node:fs/promises';

import { UsageError } from './errors.js';

/**
 * Writes a command's output file. Without `force` it uses the `wx` flag, so
 * creation is atomic: a file that appears between the command's early
 * existence check and this write is never clobbered (the race turns into the
 * same "already exists" error). With `mode`, the permissions are also
 * enforced via chmod so a forced overwrite of an existing file does not keep
 * that file's wider permissions.
 *
 * @example
 * ```ts
 * import { writeOutput } from './output.js';
 *
 * await writeOutput('note.txt', plaintext, { force: false, mode: 0o600 });
 * ```
 */
export async function writeOutput(
  path: string,
  data: Uint8Array,
  options: { force: boolean; mode?: number },
): Promise<void> {
  try {
    await writeFile(path, data, { flag: options.force ? 'w' : 'wx', mode: options.mode });
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new UsageError(`${path} already exists. Use --force to overwrite it.`);
    }
    throw cause;
  }
  if (options.mode !== undefined) {
    await chmod(path, options.mode);
  }
}
