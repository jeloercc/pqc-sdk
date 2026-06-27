import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { SUPPORTED_ALGORITHMS, pqc, type SupportedAlgorithm } from '@pqc-sdk/core';

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
    throw new Error(
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
    throw new Error('Invalid --name: must not be empty.');
  }
  if (value.includes('/') || value.includes('\\')) {
    throw new Error('Invalid --name: must not contain path separators ("/" or "\\").');
  }
  if (value.includes('..')) {
    throw new Error('Invalid --name: must not contain "..".');
  }
  return value;
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
        throw new Error(`${path} already exists. Use --force to overwrite it.`);
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
