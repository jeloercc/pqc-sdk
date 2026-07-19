import { existsSync } from 'node:fs';
import { stat } from 'node:fs/promises';

import { UsageError } from './errors.js';

/**
 * `pqc encrypt` and `pqc decrypt` buffer the whole file in memory — the core
 * API is one-shot AEAD, there is no streaming envelope yet — so inputs are
 * capped here with a clear error instead of an opaque out-of-memory crash or
 * Node's raw `ERR_FS_FILE_TOO_LARGE` past 2 GiB.
 */
export const MAX_INPUT_BYTES = 1024 * 1024 * 1024; // 1 GiB

/**
 * Asserts that a command's input file exists and is within
 * {@link MAX_INPUT_BYTES}, throwing a {@link UsageError} otherwise.
 *
 * @example
 * ```ts
 * import { assertReadableInput } from '../input.js';
 *
 * await assertReadableInput('will.pdf'); // throws UsageError if missing or > 1 GiB
 * ```
 */
export async function assertReadableInput(path: string): Promise<void> {
  if (!existsSync(path)) {
    throw new UsageError(`Input file not found: ${path}`);
  }
  const { size } = await stat(path);
  if (size > MAX_INPUT_BYTES) {
    const gib = (size / MAX_INPUT_BYTES).toFixed(2);
    throw new UsageError(
      `${path} is ${gib} GiB, above the 1 GiB limit: the CLI loads the whole file into memory (no streaming yet). Split the file or encrypt an archive of its parts.`,
    );
  }
}
