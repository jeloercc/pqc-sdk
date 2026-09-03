import { createWriteStream } from 'node:fs';
import { chmod, unlink, writeFile } from 'node:fs/promises';
import { Writable } from 'node:stream';

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

/**
 * Streaming counterpart to {@link writeOutput}: pipes a `ReadableStream`
 * (typically the output of `pqc.encryptWebStream`/`decryptWebStream`) to a
 * file, with the same atomic-creation (`wx` unless `force`) and `mode`
 * semantics, and the same clean `UsageError` on a pre-existing file. Used
 * above {@link STREAMING_THRESHOLD_BYTES} in `../input.js`, where the
 * one-shot `writeOutput` above it would hold the whole envelope in memory.
 *
 * **Cleans up on failure.** `decryptWebStream`'s incremental-release
 * property (docs/serialization-format.md §9.3) means a mid-stream failure
 * — a tampered or truncated ciphertext — can happen after some genuine
 * plaintext bytes were already written to `path`. That partial file is
 * real authenticated bytes but not a complete, trustworthy result; leaving
 * it on disk would let a caller mistake a rejected decrypt for a
 * successful (if short) one. On any failure other than the file already
 * existing, the partial file is deleted before the error propagates.
 *
 * @example
 * ```ts
 * import { pipeToOutput } from './output.js';
 *
 * await pipeToOutput(readable, 'large-file.bin.enc', { force: false });
 * ```
 */
export async function pipeToOutput(
  source: ReadableStream<Uint8Array>,
  path: string,
  options: { force: boolean; mode?: number },
): Promise<void> {
  const nodeStream = createWriteStream(path, {
    flags: options.force ? 'w' : 'wx',
    mode: options.mode,
  });
  try {
    await source.pipeTo(Writable.toWeb(nodeStream) as WritableStream<Uint8Array>);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new UsageError(`${path} already exists. Use --force to overwrite it.`);
    }
    await unlink(path).catch(() => {
      // Best-effort: the file may never have been created, or may already
      // be gone. Either way, there's nothing left to clean up.
    });
    throw cause;
  }
  if (options.mode !== undefined) {
    await chmod(path, options.mode);
  }
}
