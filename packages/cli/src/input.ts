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
 *
 * This is the *default*: `--max-size` raises or lowers it, per
 * `docs/proposals/streaming-encryption.md` §2, which specifies the ceiling
 * as overridable. Because it guards against mistakes rather than against an
 * attacker or a cryptographic bound, overriding it is a legitimate operator
 * decision — it is just never a silent one (see {@link assertReadableInput}).
 */
export const MAX_INPUT_BYTES = 1024 * 1024 * 1024 * 1024; // 1 TiB

const SIZE_UNITS: ReadonlyArray<readonly [parsed: string, display: string, multiplier: number]> = [
  ['tib', 'TiB', 1024 ** 4],
  ['gib', 'GiB', 1024 ** 3],
  ['mib', 'MiB', 1024 ** 2],
  ['kib', 'KiB', 1024],
  ['b', 'B', 1],
];

/** Renders a byte count with the largest binary unit that keeps it readable. */
export function formatSize(bytes: number): string {
  for (const [, display, multiplier] of SIZE_UNITS) {
    if (bytes >= multiplier) {
      const value = bytes / multiplier;
      return `${Number.isInteger(value) ? value : value.toFixed(2)} ${display}`;
    }
  }
  return `${bytes} B`;
}

/**
 * Parses a `--max-size` value: a plain byte count (`1099511627776`) or a
 * binary-unit shorthand (`2TiB`, `500GiB`, `64MiB`, case-insensitive, with
 * optional space). Rejects anything else with a {@link UsageError} rather
 * than silently coercing — a mistyped ceiling that parses as `NaN` would
 * disable the guard entirely.
 *
 * @example
 * ```ts
 * import { parseSize } from './input.js';
 *
 * parseSize('2TiB'); // 2199023255552
 * parseSize('500 GiB'); // 536870912000
 * ```
 */
export function parseSize(input: string): number {
  const normalized = input.trim().toLowerCase().replace(/\s+/g, '');
  const match = /^(\d+(?:\.\d+)?)(tib|gib|mib|kib|b)?$/.exec(normalized);
  if (!match) {
    throw new UsageError(
      `Invalid --max-size value: ${input}. Expected a byte count or a binary-unit size such as 2TiB, 500GiB or 64MiB.`,
    );
  }
  const amount = Number(match[1]);
  const unit = match[2] ?? 'b';
  const multiplier = SIZE_UNITS.find(([parsed]) => parsed === unit)?.[2] ?? 1;
  const bytes = Math.floor(amount * multiplier);
  if (!Number.isFinite(bytes) || bytes < 1) {
    throw new UsageError(
      `Invalid --max-size value: ${input}. The ceiling must be at least 1 byte.`,
    );
  }
  return bytes;
}

/**
 * Asserts that a command's input file exists and is within the operational
 * ceiling — {@link MAX_INPUT_BYTES} by default, or `maxBytes` when the
 * operator passed `--max-size` — throwing a {@link UsageError} otherwise,
 * and returns its size so the caller can pick the one-shot or streaming
 * path against {@link STREAMING_THRESHOLD_BYTES}.
 *
 * `onOverride` fires only when the file would have been refused by the
 * default ceiling and is being accepted solely because of `--max-size`.
 * That is the case worth announcing: raising the ceiling and then staying
 * under 1 TiB anyway changed nothing, but bypassing the sanity check
 * deserves to be said out loud rather than inferred from its absence.
 *
 * @example
 * ```ts
 * import { assertReadableInput, STREAMING_THRESHOLD_BYTES } from '../input.js';
 *
 * const size = await assertReadableInput('will.pdf'); // throws UsageError if missing or > 1 TiB
 * const streaming = size > STREAMING_THRESHOLD_BYTES;
 * ```
 */
export async function assertReadableInput(
  path: string,
  options: {
    maxBytes?: number | undefined;
    onOverride?: ((size: number, maxBytes: number) => void) | undefined;
  } = {},
): Promise<number> {
  if (!existsSync(path)) {
    throw new UsageError(`Input file not found: ${path}`);
  }
  const maxBytes = options.maxBytes ?? MAX_INPUT_BYTES;
  const { size } = await stat(path);
  if (size > maxBytes) {
    const limit = formatSize(maxBytes);
    const raise =
      maxBytes === MAX_INPUT_BYTES
        ? ' If this is genuinely intended, raise the guard with --max-size (e.g. --max-size 2TiB) or split the file.'
        : ' Raise --max-size further if this is genuinely intended.';
    throw new UsageError(
      `${path} is ${formatSize(size)}, above the ${limit} operational limit. This is a sanity check against accidental inputs (e.g. a mounted device), not a cryptographic limit — see docs/proposals/streaming-encryption.md §2.${raise}`,
    );
  }
  if (size > MAX_INPUT_BYTES) {
    options.onOverride?.(size, maxBytes);
  }
  return size;
}

/**
 * Shared `--max-size` help text, so `pqc encrypt --help` and
 * `pqc decrypt --help` describe the guard identically and both say what it
 * is for.
 */
export const MAX_SIZE_DESCRIPTION =
  'Override the 1 TiB operational size guard (e.g. 2TiB, 500GiB). This guard is a sanity check against accidental inputs such as a mounted device — not a cryptographic limit. Bypassing it prints an explicit warning.';

/**
 * Builds the {@link assertReadableInput} options for a command's
 * `--max-size` argument, including the loud notice printed when the guard is
 * actually bypassed. Shared so `encrypt` and `decrypt` cannot drift into
 * announcing an override differently — or one of them forgetting to.
 */
export function sizeGuardOptions(
  maxSize: string | undefined,
  announce: (message: string) => void,
): { maxBytes: number | undefined; onOverride: (size: number, maxBytes: number) => void } {
  return {
    maxBytes: maxSize === undefined ? undefined : parseSize(maxSize),
    onOverride: (size, maxBytes) => {
      announce(
        `Operational size guard bypassed: ${formatSize(size)} exceeds the ${formatSize(MAX_INPUT_BYTES)} default, allowed by --max-size ${formatSize(maxBytes)}. This guard protects against accidental inputs, not against a cryptographic limit — proceeding.`,
      );
    },
  };
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
