/**
 * Tool handler logic — the production handler that index.ts wires to the MCP
 * transport, exported so tests can call it without starting stdio.
 *
 * Secret keys are resolved from the keystore by `keyId`; no handler accepts
 * or returns secret key material.
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  type Algorithm,
  FIPS_ALGORITHMS,
  PqcError,
  type PqcKey,
  SUPPORTED_ALGORITHMS,
  pqc,
} from '@pqc-sdk/core';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { KEY_ID_PATTERN, type KeyStore, KeystoreError } from './keystore.js';

// ─── Context ─────────────────────────────────────────────────────────────────

/** What a handler needs besides the tool arguments. */
export interface HandlerContext {
  readonly keyStore: KeyStore;
  /** Whether `pqc_sign` may be called. */
  readonly enableSign: boolean;
}

// ─── Response helpers ─────────────────────────────────────────────────────────

function ok(data: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function fail(code: string, message: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ error: code, message }) }],
  };
}

// ─── Argument helpers ────────────────────────────────────────────────────────

/** A tool argument is missing or malformed. Mapped to `INVALID_ARGUMENT`. */
class ArgumentError extends Error {}

function requireString(args: Record<string, unknown>, field: string): string {
  const value = args[field];
  if (typeof value !== 'string') {
    throw new ArgumentError(`"${field}" is required and must be a string`);
  }
  return value;
}

function optionalString(args: Record<string, unknown>, field: string): string | undefined {
  const value = args[field];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new ArgumentError(`"${field}" must be a string`);
  }
  return value;
}

function requireKeyId(args: Record<string, unknown>): string {
  const keyId = requireString(args, 'keyId');
  // The value is not echoed: it came from the model and failed validation.
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new ArgumentError(`"keyId" must match ${KEY_ID_PATTERN.source}`);
  }
  return keyId;
}

function parseHex(value: string): Uint8Array | undefined {
  try {
    return hexToBytes(value);
  } catch {
    return undefined;
  }
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function parseBase64(value: string): Uint8Array | undefined {
  if (!BASE64_PATTERN.test(value)) return undefined;
  return new Uint8Array(Buffer.from(value, 'base64'));
}

/**
 * Returns decrypted bytes losslessly: as text when they are valid UTF-8,
 * otherwise base64. `ignoreBOM` keeps a leading U+FEFF instead of stripping it.
 */
function plaintextResult(
  bytes: Uint8Array,
): { encoding: 'utf8'; plaintext: string } | { encoding: 'base64'; plaintextBase64: string } {
  try {
    const plaintext = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return { encoding: 'utf8', plaintext };
  } catch {
    return { encoding: 'base64', plaintextBase64: Buffer.from(bytes).toString('base64') };
  }
}

// ─── Handler ─────────────────────────────────────────────────────────────────

/**
 * Runs one tool call and returns its MCP result. Failures are returned as
 * `isError` results carrying a stable error code; they are never thrown.
 *
 * @example
 * ```ts
 * import { handleTool } from './handlers.js';
 * import { FileKeyStore } from './keystore.js';
 *
 * const context = { keyStore: FileKeyStore.fromEnv(), enableSign: false };
 * const result = await handleTool('pqc_keygen', { algorithm: 'x-wing' }, context);
 * // result.content[0].text → { "keyId": "x-wing-…", "algorithm": "x-wing", "publicToken": "pqcv1.x-wing.public.…" }
 * ```
 */
export async function handleTool(
  name: string,
  args: Record<string, unknown>,
  context: HandlerContext,
): Promise<CallToolResult> {
  try {
    switch (name) {
      case 'pqc_keygen': {
        const algorithm = optionalString(args, 'algorithm') ?? 'x-wing';
        // The keystore passes the name to pqc.keys.generate, whose runtime
        // check surfaces UNSUPPORTED_ALGORITHM for anything unknown.
        const info = await context.keyStore.generate(algorithm as Algorithm);
        return ok(info);
      }

      case 'pqc_list_keys': {
        return ok({ keys: await context.keyStore.list() });
      }

      case 'pqc_encrypt': {
        const publicToken = requireString(args, 'publicToken');
        const text = optionalString(args, 'plaintext');
        const base64 = optionalString(args, 'plaintextBase64');
        if ((text === undefined) === (base64 === undefined)) {
          throw new ArgumentError('Pass exactly one of "plaintext" or "plaintextBase64"');
        }
        let data: string | Uint8Array;
        if (text !== undefined) {
          data = text;
        } else {
          const bytes = parseBase64(base64 ?? '');
          if (bytes === undefined) {
            throw new ArgumentError('"plaintextBase64" is not valid base64');
          }
          data = bytes;
        }
        const key = pqc.keys.deserialize(publicToken);
        // deserialize returns PqcKey<Algorithm, KeyUse>; encrypt accepts
        // PublicKey<KemAlgorithm>. The runtime requireKey check inside encrypt
        // handles wrong-algorithm and wrong-use errors.
        const ct = await (
          pqc.encrypt as (data: string | Uint8Array, key: PqcKey) => Promise<Uint8Array>
        )(data, key);
        return ok({ ciphertextHex: bytesToHex(ct) });
      }

      case 'pqc_decrypt': {
        const keyId = requireKeyId(args);
        const ciphertext = parseHex(requireString(args, 'ciphertextHex'));
        if (ciphertext === undefined) {
          return fail('INVALID_CIPHERTEXT', '"ciphertextHex" is not valid hex');
        }
        const key = await context.keyStore.loadSecretKey(keyId);
        const pt = await (pqc.decrypt as (ct: Uint8Array, key: PqcKey) => Promise<Uint8Array>)(
          ciphertext,
          key,
        );
        return ok(plaintextResult(pt));
      }

      case 'pqc_sign': {
        if (!context.enableSign) {
          return fail('TOOL_DISABLED', 'pqc_sign is disabled on this server');
        }
        const keyId = requireKeyId(args);
        const message = requireString(args, 'message');
        const key = await context.keyStore.loadSecretKey(keyId);
        const sig = await (pqc.sign as (data: string, key: PqcKey) => Promise<Uint8Array>)(
          message,
          key,
        );
        return ok({ signatureHex: bytesToHex(sig) });
      }

      case 'pqc_verify': {
        const message = requireString(args, 'message');
        const signatureHex = requireString(args, 'signatureHex');
        const publicToken = requireString(args, 'publicToken');
        const key = pqc.keys.deserialize(publicToken);
        const signature = parseHex(signatureHex);
        // A signature that is not even hex cannot be genuine.
        if (signature === undefined) return ok({ verified: false });
        const verified = await (
          pqc.verify as (data: string, sig: Uint8Array, key: PqcKey) => Promise<boolean>
        )(message, signature, key);
        return ok({ verified });
      }

      case 'pqc_algorithms': {
        return ok({ supported: [...SUPPORTED_ALGORITHMS], fips: [...FIPS_ALGORITHMS] });
      }

      default:
        return fail('UNKNOWN_TOOL', `Unknown tool: ${name}`);
    }
  } catch (cause) {
    if (cause instanceof PqcError || cause instanceof KeystoreError) {
      return fail(cause.code, cause.message);
    }
    if (cause instanceof ArgumentError) {
      return fail('INVALID_ARGUMENT', cause.message);
    }
    // Unexpected failures (e.g. filesystem errors) may carry local paths:
    // log the detail for the operator, return only a generic message.
    const detail = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`pqc-mcp: ${name} failed: ${detail}\n`);
    return fail('INTERNAL_ERROR', `${name} failed unexpectedly; see the server log`);
  }
}
