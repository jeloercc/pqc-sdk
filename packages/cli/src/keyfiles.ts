import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import {
  KEM_NAMES,
  SUPPORTED_ALGORITHMS,
  pqc,
  type Algorithm,
  type ExpectedKey,
  type KemAlgorithm,
  type KeyUse,
  type PqcKey,
  type SupportedAlgorithm,
} from '@pqc-sdk/core';

import { UsageError } from './errors.js';
import { warn } from './ui.js';

/** Patterns that keep generated secret keys out of version control. */
export const KEY_IGNORE_PATTERNS = ['keys/', '*.secret.pqc'] as const;

/**
 * Ensures the project `.gitignore` ignores generated key material so a secret
 * key is never committed by an accidental `git add .`. Creates `.gitignore`
 * when it is missing, or appends only the patterns not already present.
 * Idempotent. Returns the patterns it added (empty when nothing changed).
 */
export async function ensureKeysIgnored(cwd: string): Promise<string[]> {
  const gitignorePath = join(cwd, '.gitignore');
  const current = existsSync(gitignorePath) ? await readFile(gitignorePath, 'utf8') : '';
  const present = new Set(current.split(/\r?\n/).map((line) => line.trim()));
  const missing = KEY_IGNORE_PATTERNS.filter((pattern) => !present.has(pattern));
  if (missing.length === 0) {
    return [];
  }
  const prefix = current === '' ? '' : current.endsWith('\n') ? '\n' : '\n\n';
  const block = `${prefix}# PQC key material — never commit secret keys\n${missing.join('\n')}\n`;
  await writeFile(gitignorePath, current + block);
  return [...missing];
}

export interface WrittenKeyPair {
  algorithm: SupportedAlgorithm;
  publicPath: string;
  secretPath: string;
}

export function assertSupportedAlgorithm(value: string): SupportedAlgorithm {
  if (!(SUPPORTED_ALGORITHMS as readonly string[]).includes(value)) {
    throw new UsageError(
      `Unsupported algorithm: ${value} (supported: ${SUPPORTED_ALGORITHMS.join(', ')})`,
    );
  }
  return value as SupportedAlgorithm;
}

/**
 * Validates a base file name for a key pair. The name becomes part of the path
 * passed to {@link writeKeyPair}, so it must not be empty, contain path
 * separators (`/` or `\`), or contain `..` — otherwise a caller could write
 * keys outside the intended output directory.
 */
export function assertSafeName(value: string): string {
  if (value === '') {
    throw new UsageError('Invalid --name: must not be empty.');
  }
  if (value.includes('/') || value.includes('\\')) {
    throw new UsageError('Invalid --name: must not contain path separators ("/" or "\\").');
  }
  if (value.includes('..')) {
    throw new UsageError('Invalid --name: must not contain "..".');
  }
  return value;
}

/**
 * Reads a key file written by `pqc keygen` (the serialized key on one line)
 * and deserializes it, asserting the algorithm and use the caller expects.
 * Throws with the file path in the message when the file is missing or does
 * not contain the expected kind of key.
 *
 * @example
 * ```ts
 * import { readKeyFile } from './keyfiles.js';
 *
 * const publicKey = await readKeyFile('keys/ml-kem-768.public.pqc', {
 *   algorithm: 'ml-kem-768',
 *   use: 'public',
 * });
 * ```
 */
export async function readKeyFile<A extends Algorithm, U extends KeyUse>(
  path: string,
  expected: ExpectedKey<A, U>,
): Promise<PqcKey<A, U>> {
  if (!existsSync(path)) {
    throw new UsageError(`Key file not found: ${path}`);
  }
  if (expected.use === 'secret') {
    await warnIfSecretKeyTooOpen(path);
  }
  const contents = await readFile(path, 'utf8');
  try {
    return pqc.keys.deserialize(contents.trim(), expected);
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new UsageError(
      `${path} is not a valid ${expected.algorithm} ${expected.use} key: ${reason}`,
    );
  }
}

/**
 * Reads a key file written by `pqc keygen` (or the SDK) expected to be a KEM
 * key of the given use, for `pqc encrypt`/`pqc decrypt`. Unlike
 * {@link readKeyFile}, it does not pin a single algorithm: any KEM
 * (`ml-kem-768` or `x-wing`) is accepted, and `pqc.encrypt`/`pqc.decrypt`
 * themselves pick the matching envelope version from the key
 * (docs/serialization-format.md §2). Throws {@link UsageError}, naming the
 * algorithm actually found, when the file holds a signing key or the wrong
 * use.
 *
 * @example
 * ```ts
 * import { readKemKeyFile } from './keyfiles.js';
 *
 * const publicKey = await readKemKeyFile('keys/alice.public.pqc', 'public');
 * ```
 */
export async function readKemKeyFile<U extends KeyUse>(
  path: string,
  use: U,
): Promise<PqcKey<KemAlgorithm, U>> {
  if (!existsSync(path)) {
    throw new UsageError(`Key file not found: ${path}`);
  }
  if (use === 'secret') {
    await warnIfSecretKeyTooOpen(path);
  }
  const contents = await readFile(path, 'utf8');
  let key: PqcKey;
  try {
    key = pqc.keys.deserialize(contents.trim());
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new UsageError(`${path} is not a valid PQC key: ${reason}`);
  }
  if (key.use !== use) {
    throw new UsageError(`${path} is a ${key.use} key; a ${use} key is required here.`);
  }
  if (!(KEM_NAMES as readonly string[]).includes(key.algorithm)) {
    throw new UsageError(
      `${path} is a ${key.algorithm} key, which cannot be used for encryption. ` +
        `Use a KEM key (${KEM_NAMES.join(' or ')}).`,
    );
  }
  return key as PqcKey<KemAlgorithm, U>;
}

/**
 * Warns (ssh-style, without refusing) when a secret key file is readable or
 * writable by group/others. `pqc keygen` writes secret keys with mode 0600,
 * but a key that was copied, restored from a backup, or checked out of version
 * control can lose that. Skipped on Windows, where POSIX mode bits are not
 * meaningful.
 */
async function warnIfSecretKeyTooOpen(path: string): Promise<void> {
  if (process.platform === 'win32') {
    return;
  }
  const mode = (await stat(path)).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    const octal = mode.toString(8).padStart(4, '0');
    warn(
      `Permissions ${octal} for ${path} are too open: the secret key should be accessible only by you. Fix it with: chmod 600 ${path}`,
    );
  }
}

/** Generates a pair and writes it serialized as base64url, one file per key. */
export async function writeKeyPair(
  directory: string,
  baseName: string,
  algorithm: SupportedAlgorithm,
  force: boolean,
): Promise<WrittenKeyPair> {
  const publicPath = join(directory, `${baseName}.public.pqc`);
  const secretPath = join(directory, `${baseName}.secret.pqc`);

  if (!force) {
    for (const path of [publicPath, secretPath]) {
      if (existsSync(path)) {
        throw new UsageError(`${path} already exists. Use --force to overwrite it.`);
      }
    }
  }

  const pair = await pqc.keys.generate({ algorithm });
  await mkdir(directory, { recursive: true });
  await writeFile(publicPath, `${pqc.keys.serialize(pair.publicKey)}\n`);
  await writeFile(secretPath, `${pqc.keys.serialize(pair.secretKey)}\n`, { mode: 0o600 });
  await chmod(secretPath, 0o600);

  return { algorithm, publicPath, secretPath };
}
