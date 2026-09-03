import { existsSync } from 'node:fs';
import { open, stat } from 'node:fs/promises';

import { UsageError } from './errors.js';

/**
 * `pqc encrypt` picks the envelope by input size (docs/proposals/streaming-encryption.md
 * §3): at or below this, the existing one-shot `pqc.encrypt` path (v1/v2) —
 * simpler, already battle-tested, negligible RAM cost at this size. Above
 * it, the streaming path (`pqc.encryptWebStream`, v3/v4), bounding CLI
 * memory to roughly one chunk regardless of file size.
 */
export const STREAMING_THRESHOLD_BYTES = 8 * 1024 * 1024; // 8 MiB

/**
 * A generous **operational** sanity ceiling against operator mistakes (e.g.
 * pointing the CLI at a mounted block device) — not a cryptographic limit.
 * The streaming envelope itself has no practical size ceiling (§9.5): the
 * 11-byte chunk counter's `2^88` index space and per-stream KEM freshness
 * mean there is no "total bytes under one key" concern to manage.
 */
export const MAX_INPUT_BYTES = 1024 * 1024 * 1024 * 1024; // 1 TiB

/**
 * Asserts that a command's input file exists and is within
 * {@link MAX_INPUT_BYTES}, throwing a {@link UsageError} otherwise, and
 * returns its size so the caller can pick the one-shot or streaming path
 * against {@link STREAMING_THRESHOLD_BYTES}.
 *
 * @example
 * ```ts
 * import { assertReadableInput, STREAMING_THRESHOLD_BYTES } from '../input.js';
 *
 * const size = await assertReadableInput('will.pdf'); // throws UsageError if missing or > 1 TiB
 * const streaming = size > STREAMING_THRESHOLD_BYTES;
 * ```
 */
export async function assertReadableInput(path: string): Promise<number> {
  if (!existsSync(path)) {
    throw new UsageError(`Input file not found: ${path}`);
  }
  const { size } = await stat(path);
  if (size > MAX_INPUT_BYTES) {
    const tib = (size / MAX_INPUT_BYTES).toFixed(2);
    throw new UsageError(
      `${path} is ${tib} TiB, above the 1 TiB operational limit. This is a sanity check against accidental inputs (e.g. a mounted device), not a cryptographic limit — see docs/proposals/streaming-encryption.md §2. If this is genuinely intended, split the file.`,
    );
  }
  return size;
}

/**
 * Reads the leading envelope version byte without loading the rest of the
 * file — enough for `pqc decrypt` to dispatch between the one-shot
 * (`0x01`/`0x02`) and streaming (`0x03`/`0x04`) decoders
 * (docs/serialization-format.md §2, §9) before committing to either code
 * path. An empty or unreadable file surfaces the same `UsageError` either
 * decoder would eventually give for a too-short envelope.
 */
export async function peekEnvelopeVersion(path: string): Promise<number> {
  const fd = await open(path, 'r');
  try {
    const buf = new Uint8Array(1);
    const { bytesRead } = await fd.read(buf, 0, 1, 0);
    if (bytesRead < 1) {
      throw new UsageError(
        `${path} is empty or truncated: not a valid pqc envelope produced by \`pqc encrypt\`.`,
      );
    }
    return buf[0]!;
  } finally {
    await fd.close();
  }
}
