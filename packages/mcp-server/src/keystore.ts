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
 *
 * On POSIX the directory is also checked on every call, in the spirit of
 * OpenSSH's StrictModes: the configured path must not be a symlink, the
 * keystore directory must belong to the server's user, and no ancestor may
 * let another user replace it (see {@link ancestorDirectoryProblem}).
 */

import { constants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { chmod, link, lstat, mkdir, open, readdir, realpath, stat, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

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

/** Environment variable that caps how many keys the keystore may hold. */
export const MAX_KEYS_ENV = 'PQC_MCP_MAX_KEYS';

/** Cap used when {@link MAX_KEYS_ENV} is unset. */
export const DEFAULT_MAX_KEYS = 100;

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
  'INVALID_ARGUMENT' | 'KEY_NOT_FOUND' | 'KEYSTORE_INSECURE' | 'KEYSTORE_FULL' | 'INVALID_KEY_FILE';

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

/**
 * Parses {@link MAX_KEYS_ENV}: unset or empty means {@link DEFAULT_MAX_KEYS};
 * anything but a positive integer is a configuration error. The message is
 * operator-facing (it goes to stderr at startup, never to the model).
 */
export function parseMaxKeys(raw: string | undefined): number {
  if (raw === undefined || raw === '') return DEFAULT_MAX_KEYS;
  const value = Number(raw);
  if (!/^[1-9][0-9]*$/.test(raw) || !Number.isSafeInteger(value)) {
    throw new Error(`${MAX_KEYS_ENV} must be a positive integer, got "${raw}"`);
  }
  return value;
}

// ─── Permission policy (POSIX) ───────────────────────────────────────────────
//
// Pure functions over stat data, so every rule — including the ones that need
// another user or root to reproduce on a real filesystem — can be tested with
// synthetic stats through the same code the keystore runs.

/** The `stat` fields the permission policy looks at. */
export interface StatLike {
  readonly mode: number;
  readonly uid: number;
}

const GROUP_OR_OTHER_WRITE = 0o022;
const STICKY = 0o1000;

/**
 * The keystore directory itself must belong to the server's user and not be
 * writable by group or others. Returns what is wrong, or `undefined`.
 */
export function keystoreDirectoryProblem(info: StatLike, serverUid: number): string | undefined {
  if (info.uid !== serverUid) return "is not owned by the server's user";
  if ((info.mode & GROUP_OR_OTHER_WRITE) !== 0) return 'is writable by group or others';
  return undefined;
}

/**
 * Every ancestor of the keystore must belong to root or the server's user,
 * and must not let another user rename or replace the entry beneath it: not
 * writable by group or others, **unless the sticky bit is set**.
 *
 * Why the sticky exception is safe: in a sticky directory (e.g. `/tmp`, mode
 * `1777`) other users may create entries but cannot rename or delete entries
 * they do not own, so a keystore directory we own cannot be swapped out from
 * under us. What another user *can* do there is create the path first, before
 * the server does — and that is caught by {@link keystoreDirectoryProblem}:
 * the keystore directory must be owned by the server's user, so a directory
 * pre-created by someone else is refused.
 */
export function ancestorDirectoryProblem(info: StatLike, serverUid: number): string | undefined {
  if (info.uid !== 0 && info.uid !== serverUid) return 'is owned by another user';
  if ((info.mode & GROUP_OR_OTHER_WRITE) !== 0 && (info.mode & STICKY) === 0) {
    return 'is writable by group or others (and not sticky)';
  }
  return undefined;
}

/**
 * A public key file must belong to the server's user and not be writable by
 * group or others, so nobody else can plant the public key the model will
 * encrypt to. Group/other *read* access is fine for a public key.
 */
export function publicFileProblem(info: StatLike, serverUid: number): string | undefined {
  if (info.uid !== serverUid) return "is not owned by the server's user";
  if ((info.mode & GROUP_OR_OTHER_WRITE) !== 0) return 'is writable by group or others';
  return undefined;
}

/**
 * Applies the directory policy to a keystore and its ancestors (nearest
 * first). Returns the first violation, or `undefined` when all pass.
 */
export function directoryChainProblem(
  keystore: StatLike,
  ancestors: readonly (StatLike & { readonly path: string })[],
  serverUid: number,
): { readonly path?: string; readonly problem: string } | undefined {
  const own = keystoreDirectoryProblem(keystore, serverUid);
  if (own !== undefined) return { problem: `the keystore directory ${own}` };
  for (const ancestor of ancestors) {
    const problem = ancestorDirectoryProblem(ancestor, serverUid);
    if (problem !== undefined) {
      return { path: ancestor.path, problem: `a parent directory of the keystore ${problem}` };
    }
  }
  return undefined;
}

/** Every directory above `path`, nearest first, up to the filesystem root. */
function parentDirectories(path: string): string[] {
  const parents: string[] = [];
  for (let current = dirname(path); ; current = dirname(current)) {
    parents.push(current);
    if (dirname(current) === current) return parents;
  }
}

export interface FileKeyStoreOptions {
  /** Sink for operator-facing warnings. Default: one line on stderr. */
  readonly warn?: (message: string) => void;
  /** Maximum number of keys `generate` may leave in the keystore. Default: 100. */
  readonly maxKeys?: number;
}

/**
 * Keystore backed by a directory of CLI-format key files.
 *
 * Directories it creates are `0700` and files `0600`. On POSIX it refuses to
 * work in a keystore whose path is a symlink, whose directory is not owned by
 * the server's user or is writable by group or others, or whose ancestors let
 * another user replace it; it refuses to load a secret key file that is a
 * symlink, not owned by the server's user, or accessible by group or others;
 * and it skips (with a warning) a public key file that another user owns or
 * can write.
 */
export class FileKeyStore implements KeyStore {
  readonly directory: string;
  readonly maxKeys: number;
  readonly #warn: (message: string) => void;
  readonly #warned = new Set<string>();
  /** Serializes generate() so concurrent calls cannot exceed maxKeys. */
  #generating: Promise<unknown> = Promise.resolve();

  constructor(directory: string, options: FileKeyStoreOptions = {}) {
    this.directory = resolve(directory);
    const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    if (!Number.isSafeInteger(maxKeys) || maxKeys < 1) {
      throw new RangeError(`maxKeys must be a positive integer, got ${String(maxKeys)}`);
    }
    this.maxKeys = maxKeys;
    this.#warn =
      options.warn ??
      ((message) => {
        process.stderr.write(`pqc-mcp: ${message}\n`);
      });
  }

  /**
   * Builds a keystore from {@link KEYSTORE_DIR_ENV} (or the default directory)
   * and {@link MAX_KEYS_ENV}. Throws on an invalid {@link MAX_KEYS_ENV}.
   */
  static fromEnv(
    env: NodeJS.ProcessEnv = process.env,
    options: FileKeyStoreOptions = {},
  ): FileKeyStore {
    const configured = env[KEYSTORE_DIR_ENV];
    const directory = configured ? configured : defaultKeystoreDir(env);
    return new FileKeyStore(directory, { maxKeys: parseMaxKeys(env[MAX_KEYS_ENV]), ...options });
  }

  generate(algorithm: Algorithm): Promise<KeyInfo> {
    const run = this.#generating.then(() => this.#generateLocked(algorithm));
    this.#generating = run.catch(() => undefined);
    return run;
  }

  async #generateLocked(algorithm: Algorithm): Promise<KeyInfo> {
    // Generate first: an unsupported algorithm fails before anything touches disk.
    const pair = await pqc.keys.generate({ algorithm });
    const publicToken = pqc.keys.serialize(pair.publicKey);
    const secretToken = pqc.keys.serialize(pair.secretKey);

    await this.#ensureDirectory();
    const held = (await readdir(this.directory)).filter(
      (name) =>
        name.endsWith(SECRET_SUFFIX) && KEY_ID_PATTERN.test(name.slice(0, -SECRET_SUFFIX.length)),
    ).length;
    if (held >= this.maxKeys) {
      throw new KeystoreError(
        'KEYSTORE_FULL',
        `The keystore holds ${held} keys (limit ${this.maxKeys}); remove unused keys or raise ${MAX_KEYS_ENV}`,
      );
    }

    for (let attempt = 0; attempt < 5; attempt++) {
      const keyId = `${algorithm}-${bytesToHex(randomBytes(6))}`;
      const secretPath = this.#path(keyId, SECRET_SUFFIX);
      try {
        // Secret first: list() only shows ids whose public file exists, so a
        // listed key always has its secret on disk.
        await this.writeExclusive(secretPath, `${secretToken}\n`);
      } catch (cause) {
        if (isErrno(cause, 'EEXIST')) continue;
        throw cause;
      }
      try {
        await this.writeExclusive(this.#path(keyId, PUBLIC_SUFFIX), `${publicToken}\n`);
      } catch (cause) {
        // Do not leave an unlisted, unusable secret key behind.
        await unlink(secretPath).catch(() => {
          this.#warn(
            `could not remove the secret key file for "${keyId}" after its public key file failed to write; remove it manually`,
          );
        });
        throw cause;
      }
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
      if (suffix === SECRET_SUFFIX) {
        // Listed through its public file; a secret without one is an orphan.
        if (!present.has(`${keyId}${PUBLIC_SUFFIX}`)) {
          this.#warnOnce(
            `secret key file for "${keyId}" has no public key file, so the key is not listed; remove it or restore its public file`,
          );
        }
        continue;
      }
      if (!present.has(`${keyId}${SECRET_SUFFIX}`)) {
        this.#warnOnce(`ignoring key "${keyId}": public key file has no matching secret key file`);
        continue;
      }
      let token: string;
      try {
        token = await this.#readPublicFile(keyId);
      } catch (cause) {
        const reason =
          cause instanceof KeystoreError ? cause.message : 'public key file could not be read';
        this.#warnOnce(`ignoring key "${keyId}": ${reason}`);
        continue;
      }
      let key: PqcKey;
      try {
        key = pqc.keys.deserialize(token);
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

  /**
   * Checks the keystore path on every call. Errors returned to the model name
   * no paths; the offending path goes to the operator's log instead.
   */
  async #checkDirectory(): Promise<void> {
    const info = await lstat(this.directory); // ENOENT propagates to callers
    if (info.isSymbolicLink()) {
      this.#warnOnce(`the keystore path ${this.directory} is a symlink; configure its real path`);
      throw new KeystoreError(
        'KEYSTORE_INSECURE',
        'The keystore path is a symlink; configure its real path (see the server log)',
      );
    }
    if (!info.isDirectory()) {
      throw new KeystoreError('KEYSTORE_INSECURE', 'The keystore path is not a directory');
    }
    if (!IS_POSIX || process.getuid === undefined) return;

    // Ancestors of both the configured path and its real path: a symlinked
    // ancestor (macOS /var -> /private/var) is checked where it points, and
    // the directory holding the symlink is checked too.
    const real = await realpath(this.directory);
    const paths = [...new Set([...parentDirectories(this.directory), ...parentDirectories(real)])];
    const ancestors = await Promise.all(
      paths.map(async (path) => {
        const { mode, uid } = await stat(path);
        return { path, mode, uid };
      }),
    );
    const violation = directoryChainProblem(info, ancestors, process.getuid());
    if (violation !== undefined) {
      if (violation.path !== undefined) {
        this.#warnOnce(`${violation.problem}: ${violation.path}`);
      }
      throw new KeystoreError(
        'KEYSTORE_INSECURE',
        `${violation.problem.charAt(0).toUpperCase()}${violation.problem.slice(1)} (see the server log)`,
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

  /** Reads a public key file, refusing symlinks and files another user controls. */
  async #readPublicFile(keyId: string): Promise<string> {
    let handle: FileHandle;
    try {
      handle = await open(this.#path(keyId, PUBLIC_SUFFIX), OPEN_NO_FOLLOW);
    } catch (cause) {
      if (isErrno(cause, 'ELOOP')) {
        throw new KeystoreError('KEYSTORE_INSECURE', 'public key file is a symlink');
      }
      throw cause;
    }
    try {
      const info = await handle.stat();
      if (!info.isFile()) {
        throw new KeystoreError('KEYSTORE_INSECURE', 'public key file is not a regular file');
      }
      if (IS_POSIX && process.getuid !== undefined) {
        const problem = publicFileProblem(info, process.getuid());
        if (problem !== undefined) {
          throw new KeystoreError('KEYSTORE_INSECURE', `public key file ${problem}`);
        }
      }
      return (await handle.readFile('utf8')).trim();
    } finally {
      await handle.close();
    }
  }

  /**
   * Writes `contents` to `path` atomically without ever replacing an
   * existing file: write a private temp file, fsync, then hard-link it into
   * place (`link` fails with EEXIST rather than overwriting). Protected so
   * tests can inject write failures.
   */
  protected async writeExclusive(path: string, contents: string): Promise<void> {
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
