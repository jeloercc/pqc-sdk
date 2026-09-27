/**
 * File-backed keystore for the MCP server.
 *
 * Secret keys stay on disk and never enter the model context: tools refer to
 * a key only by its `keyId`. The on-disk format is the one `pqc keygen`
 * writes (packages/cli/src/keyfiles.ts) — `<keyId>.public.pqc` and
 * `<keyId>.secret.pqc`, one serialized key token per file — so keys created
 * with the CLI load without ever passing through the model.
 *
 * Every lookup reads from disk; nothing is cached in memory, so keys survive
 * a server restart and operator changes to the directory take effect on the
 * next call.
 */

import { constants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { chmod, link, mkdir, open, readdir, stat, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { type Algorithm, type PqcKey, type SecretKey, pqc } from '@pqc-sdk/core';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

/**
 * Valid key ids: 1–64 characters, starting with a letter or digit, then
 * letters, digits, `_` or `-`. Dots and path separators are excluded, which
 * rules out path traversal and any clash with the `.public.pqc` /
 * `.secret.pqc` suffixes. The CLI accepts a wider set of names (e.g.
 * `alice.work`); such files are ignored by this keystore.
 */
export const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Environment variable that selects the keystore directory. */
export const KEYSTORE_DIR_ENV = 'PQC_KEYSTORE_DIR';

const PUBLIC_SUFFIX = '.public.pqc';
const SECRET_SUFFIX = '.secret.pqc';
const IS_POSIX = process.platform !== 'win32';
// O_NOFOLLOW is undefined on Windows; there the symlink check is skipped.
const OPEN_NO_FOLLOW = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);

/** Public metadata for a stored key — everything a tool may return. */
export interface KeyInfo {
  readonly keyId: string;
  readonly algorithm: Algorithm;
  readonly publicToken: string;
}

/** The keystore operations the tool handlers depend on. */
export interface KeyStore {
  generate(algorithm: Algorithm): Promise<KeyInfo>;
  list(): Promise<KeyInfo[]>;
  loadSecretKey(keyId: string): Promise<SecretKey>;
}

export type KeystoreErrorCode =
  'INVALID_ARGUMENT' | 'KEY_NOT_FOUND' | 'KEYSTORE_INSECURE' | 'INVALID_KEY_FILE';

/**
 * Keystore failure. Messages carry only the key id (already validated
 * against {@link KEY_ID_PATTERN}) and remediation hints — never file
 * contents or filesystem paths, because they are returned to the model.
 */
export class KeystoreError extends Error {
  readonly code: KeystoreErrorCode;

  constructor(code: KeystoreErrorCode, message: string) {
    super(message);
    this.name = 'KeystoreError';
    this.code = code;
  }
}

function isErrno(cause: unknown, code: string): boolean {
  return cause instanceof Error && (cause as NodeJS.ErrnoException).code === code;
}

/**
 * The directory used when {@link KEYSTORE_DIR_ENV} is unset: a dedicated
 * per-user data directory, never the CLI's `./keys`.
 */
export function defaultKeystoreDir(env: NodeJS.ProcessEnv = process.env): string {
  if (process.platform === 'win32') {
    const base = env['LOCALAPPDATA'] || join(homedir(), 'AppData', 'Local');
    return join(base, 'pqc-sdk', 'agent-keys');
  }
  const base = env['XDG_DATA_HOME'] || join(homedir(), '.local', 'share');
  return join(base, 'pqc-sdk', 'agent-keys');
}

export interface FileKeyStoreOptions {
  /** Sink for operator-facing warnings. Default: one line on stderr. */
  readonly warn?: (message: string) => void;
}

/**
 * Keystore backed by a directory of CLI-format key files.
 *
 * Directories it creates are `0700` and files `0600`. On POSIX it refuses to
 * load a secret key when the directory is writable by group or others, the
 * file is readable or writable by group or others, the file is a symlink, or
 * the file is not owned by the server's user.
 */
export class FileKeyStore implements KeyStore {
  readonly directory: string;
  readonly #warn: (message: string) => void;
  readonly #warned = new Set<string>();

  constructor(directory: string, options: FileKeyStoreOptions = {}) {
    this.directory = resolve(directory);
    this.#warn =
      options.warn ??
      ((message) => {
        process.stderr.write(`pqc-mcp: ${message}\n`);
      });
  }

  /** Builds a keystore from {@link KEYSTORE_DIR_ENV}, or the default directory. */
  static fromEnv(
    env: NodeJS.ProcessEnv = process.env,
    options?: FileKeyStoreOptions,
  ): FileKeyStore {
    const configured = env[KEYSTORE_DIR_ENV];
    const directory = configured ? configured : defaultKeystoreDir(env);
    return new FileKeyStore(directory, options);
  }

  async generate(algorithm: Algorithm): Promise<KeyInfo> {
    // Generate first: an unsupported algorithm fails before anything touches disk.
    const pair = await pqc.keys.generate({ algorithm });
    const publicToken = pqc.keys.serialize(pair.publicKey);
    const secretToken = pqc.keys.serialize(pair.secretKey);

    await this.#ensureDirectory();
    for (let attempt = 0; attempt < 5; attempt++) {
      const keyId = `${algorithm}-${bytesToHex(randomBytes(6))}`;
      try {
        // Secret first: list() only shows ids whose public file exists, so a
        // listed key always has its secret on disk.
        await this.#writeExclusive(this.#path(keyId, SECRET_SUFFIX), `${secretToken}\n`);
      } catch (cause) {
        if (isErrno(cause, 'EEXIST')) continue;
        throw cause;
      }
      await this.#writeExclusive(this.#path(keyId, PUBLIC_SUFFIX), `${publicToken}\n`);
      return { keyId, algorithm, publicToken };
    }
    throw new Error('could not allocate a unique keyId');
  }

  async list(): Promise<KeyInfo[]> {
    let names: string[];
    try {
      await this.#checkDirectory();
      names = await readdir(this.directory);
    } catch (cause) {
      if (isErrno(cause, 'ENOENT')) return [];
      throw cause;
    }

    const present = new Set(names);
    const keys: KeyInfo[] = [];
    for (const name of names) {
      const suffix = name.endsWith(PUBLIC_SUFFIX)
        ? PUBLIC_SUFFIX
        : name.endsWith(SECRET_SUFFIX)
          ? SECRET_SUFFIX
          : undefined;
      if (suffix === undefined) continue;
      const keyId = name.slice(0, -suffix.length);
      if (!KEY_ID_PATTERN.test(keyId)) {
        this.#warnOnce(
          `ignoring key file "${name}": key ids must match ${KEY_ID_PATTERN.source} (rename the file pair to use it)`,
        );
        continue;
      }
      if (suffix === SECRET_SUFFIX) continue; // listed through its public file
      if (!present.has(`${keyId}${SECRET_SUFFIX}`)) {
        this.#warnOnce(`ignoring key "${keyId}": public key file has no matching secret key file`);
        continue;
      }
      let key: PqcKey;
      try {
        key = pqc.keys.deserialize(await this.#readFile(this.#path(keyId, PUBLIC_SUFFIX)));
      } catch {
        this.#warnOnce(`ignoring key "${keyId}": public key file is not a valid public key`);
        continue;
      }
      if (key.use !== 'public') {
        this.#warnOnce(`ignoring key "${keyId}": public key file does not hold a public key`);
        continue;
      }
      keys.push({ keyId, algorithm: key.algorithm, publicToken: pqc.keys.serialize(key) });
    }
    return keys.sort((a, b) => (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0));
  }

  async loadSecretKey(keyId: string): Promise<SecretKey> {
    if (!KEY_ID_PATTERN.test(keyId)) {
      throw new KeystoreError('INVALID_ARGUMENT', `keyId must match ${KEY_ID_PATTERN.source}`);
    }
    const notFound = new KeystoreError('KEY_NOT_FOUND', `No key with keyId "${keyId}"`);
    try {
      await this.#checkDirectory();
    } catch (cause) {
      if (isErrno(cause, 'ENOENT')) throw notFound;
      throw cause;
    }

    let handle: FileHandle;
    try {
      handle = await open(this.#path(keyId, SECRET_SUFFIX), OPEN_NO_FOLLOW);
    } catch (cause) {
      if (isErrno(cause, 'ENOENT')) throw notFound;
      if (isErrno(cause, 'ELOOP')) {
        throw new KeystoreError(
          'KEYSTORE_INSECURE',
          `The secret key file for "${keyId}" is a symlink; symlinks are rejected`,
        );
      }
      throw cause;
    }

    let contents: string;
    try {
      const info = await handle.stat();
      if (!info.isFile()) {
        throw new KeystoreError(
          'KEYSTORE_INSECURE',
          `The secret key file for "${keyId}" is not a regular file`,
        );
      }
      if (IS_POSIX) {
        if ((info.mode & 0o077) !== 0) {
          throw new KeystoreError(
            'KEYSTORE_INSECURE',
            `The secret key file for "${keyId}" is accessible by group or others; fix with chmod 600`,
          );
        }
        if (process.getuid !== undefined && info.uid !== process.getuid()) {
          throw new KeystoreError(
            'KEYSTORE_INSECURE',
            `The secret key file for "${keyId}" is not owned by the server's user`,
          );
        }
      }
      contents = await handle.readFile('utf8');
    } finally {
      await handle.close();
    }

    let key: PqcKey;
    try {
      key = pqc.keys.deserialize(contents.trim());
    } catch {
      throw new KeystoreError(
        'INVALID_KEY_FILE',
        `The secret key file for "${keyId}" does not hold a valid key`,
      );
    }
    if (key.use !== 'secret') {
      throw new KeystoreError(
        'INVALID_KEY_FILE',
        `The secret key file for "${keyId}" does not hold a secret key`,
      );
    }
    return key as SecretKey;
  }

  #path(keyId: string, suffix: string): string {
    return join(this.directory, `${keyId}${suffix}`);
  }

  #warnOnce(message: string): void {
    if (this.#warned.has(message)) return;
    this.#warned.add(message);
    this.#warn(message);
  }

  async #checkDirectory(): Promise<void> {
    const info = await stat(this.directory);
    if (!info.isDirectory()) {
      throw new KeystoreError('KEYSTORE_INSECURE', 'The keystore path is not a directory');
    }
    if (IS_POSIX && (info.mode & 0o022) !== 0) {
      throw new KeystoreError(
        'KEYSTORE_INSECURE',
        'The keystore directory is writable by group or others; fix with chmod go-w',
      );
    }
  }

  async #ensureDirectory(): Promise<void> {
    const created = await mkdir(this.directory, { recursive: true, mode: 0o700 });
    if (created !== undefined) {
      // mkdir's mode is filtered by the umask; chmod pins it.
      await chmod(this.directory, 0o700);
    }
    await this.#checkDirectory();
  }

  async #readFile(path: string): Promise<string> {
    const handle = await open(path, OPEN_NO_FOLLOW);
    try {
      return (await handle.readFile('utf8')).trim();
    } finally {
      await handle.close();
    }
  }

  /**
   * Writes `contents` to `path` atomically without ever replacing an
   * existing file: write a private temp file, fsync, then hard-link it into
   * place (`link` fails with EEXIST rather than overwriting).
   */
  async #writeExclusive(path: string, contents: string): Promise<void> {
    const temp = join(this.directory, `.tmp-${bytesToHex(randomBytes(8))}`);
    const handle = await open(temp, 'wx', 0o600);
    try {
      await handle.writeFile(contents);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await chmod(temp, 0o600);
      await link(temp, path);
    } finally {
      await unlink(temp);
    }
  }
}
