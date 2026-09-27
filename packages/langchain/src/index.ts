/**
 * @pqc-sdk/langchain
 *
 * LangChain / LangGraph structured tool wrappers for @pqc-sdk/core.
 * Each tool is a Zod-typed DynamicStructuredTool compatible with:
 *   - createReactAgent / AgentExecutor (LangChain)
 *   - ToolNode / StateGraph (LangGraph)
 *   - Any framework built on @langchain/core
 *
 * Export summary:
 *   createPqcTools    — the tool set, wired to your secret-key storage
 *   pqcEncryptTool    — encrypt text or binary data (stateless)
 *   pqcVerifyTool     — verify a signature (stateless)
 *   pqcAlgorithmsTool — list supported algorithms (stateless)
 *
 * Security contract:
 *   - Secret keys never pass through the model context. No tool accepts or
 *     returns secret key material: tools refer to secret keys by `keyId`, and
 *     the keys themselves move only through callbacks you provide
 *     (`resolveSecretKey`, `onSecretKey`). This package performs no I/O.
 *   - `pqc_sign` is excluded unless you opt in with `enableSign: true`.
 *   - All errors propagate as thrown errors with a structured
 *     `PqcError[CODE]: message` prefix so the agent's error handler can branch.
 */

import { type StructuredToolInterface, tool } from '@langchain/core/tools';
import {
  type Algorithm,
  FIPS_ALGORITHMS,
  PqcError,
  type PqcKey,
  SUPPORTED_ALGORITHMS,
  type SecretKey,
  pqc,
} from '@pqc-sdk/core';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
// @langchain/core expects Zod v3 schemas. Import from the v3 compatibility
// subpath so the types align even when the root project installs Zod v4.
import { z } from 'zod/v3';

// ─── Schema cast helper ───────────────────────────────────────────────────────
//
// @langchain/core's internal ZodV3ObjectLike type requires _def.description to
// be `string`, but zod/v3 types it as `string | undefined`. This is a type-level
// incompatibility that does not affect runtime behavior.
//
// asToolSchema() is a zero-cost identity function whose return type is widened
// to `unknown` so the assignment sites don't trigger no-unsafe-assignment. The
// The ts-expect-error on each `schema:` line handles the remaining TS overload
// mismatch at precisely the call site that needs it. Every exported tool is
// annotated as StructuredToolInterface, so no Zod type reaches the published
// declarations.
function asToolSchema<T>(schema: T): unknown {
  return schema;
}

// Because the schema argument is typed `unknown`, `tool()` resolves to its
// string-input overload and reports a DynamicTool. At runtime a Zod object
// schema always yields a DynamicStructuredTool; asStructuredTool() restores
// that type so the public declarations carry only @langchain/core types.
function asStructuredTool(built: unknown): StructuredToolInterface {
  return built as StructuredToolInterface;
}

// ─── Shared definitions ───────────────────────────────────────────────────────

/**
 * Valid key ids: 1–64 characters, starting with a letter or digit, then
 * letters, digits, `_` or `-`. Checked before `resolveSecretKey` is called,
 * so the callback never sees a path separator or `..`.
 */
export const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

const AlgorithmSchema = z
  .enum([
    'ml-kem-512',
    'ml-kem-768',
    'ml-kem-1024',
    'x-wing',
    'ml-dsa-44',
    'ml-dsa-65',
    'ml-dsa-87',
  ])
  .default('x-wing')
  .describe(
    'Algorithm to use. For encryption: x-wing (PQ+classical hybrid, default), ' +
      'ml-kem-768 (FIPS 203 cat.3), ml-kem-512 (lighter, cat.1), ml-kem-1024 (strongest, cat.5). ' +
      'For signatures: ml-dsa-65 (recommended, FIPS 204 cat.3).',
  );

type AlgorithmInput = z.infer<typeof AlgorithmSchema>;

const KeyIdSchema = z
  .string()
  .describe('Id of a stored key, as returned by pqc_keygen or provided by the application.');

// ─── Error helpers ────────────────────────────────────────────────────────────

function toolError(code: string, message: string): Error {
  return new Error(`PqcError[${code}]: ${message}`);
}

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (cause) {
    if (cause instanceof PqcError) {
      throw toolError(cause.code, cause.message);
    }
    throw cause;
  }
}

function requireKeyId(keyId: string): string {
  // The value is not echoed: it came from the model and failed validation.
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw toolError('INVALID_ARGUMENT', `keyId must match ${KEY_ID_PATTERN.source}`);
  }
  return keyId;
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64(value: string): Uint8Array | undefined {
  if (!BASE64_PATTERN.test(value)) return undefined;
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
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
    return { encoding: 'base64', plaintextBase64: encodeBase64(bytes) };
  }
}

// ─── Stateless tools ──────────────────────────────────────────────────────────

/**
 * Encrypt data for a recipient.
 *
 * Pass exactly one of `plaintext` (UTF-8 text) or `plaintextBase64` (binary
 * data). The result (`ciphertextHex`) can only be decrypted by the holder of
 * the matching secret key. Safe to transmit over any channel.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 * import { pqcEncryptTool } from '@pqc-sdk/langchain';
 *
 * const pair = await pqc.keys.generate();
 * const publicToken = pqc.keys.serialize(pair.publicKey);
 * const result = await pqcEncryptTool.invoke({ publicToken, plaintext: 'hello' });
 * // result → '{"ciphertextHex":"…"}'
 * ```
 */
export const pqcEncryptTool: StructuredToolInterface = asStructuredTool(
  tool(
    (input: {
      publicToken: string;
      plaintext?: string | undefined;
      plaintextBase64?: string | undefined;
    }) =>
      run(async () => {
        const { publicToken, plaintext, plaintextBase64 } = input;
        if ((plaintext === undefined) === (plaintextBase64 === undefined)) {
          throw toolError('INVALID_ARGUMENT', 'Pass exactly one of plaintext or plaintextBase64');
        }
        let data: string | Uint8Array;
        if (plaintext !== undefined) {
          data = plaintext;
        } else {
          const bytes = decodeBase64(plaintextBase64 ?? '');
          if (bytes === undefined) {
            throw toolError('INVALID_ARGUMENT', 'plaintextBase64 is not valid base64');
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
        return JSON.stringify({ ciphertextHex: bytesToHex(ct) });
      }),
    {
      name: 'pqc_encrypt',
      description:
        'Encrypt data for a recipient using their public key token. Only the holder of the ' +
        'matching secret key can decrypt. Pass exactly one of plaintext (UTF-8 text) or ' +
        'plaintextBase64 (binary data). Quantum-resistant.',
      // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
      schema: asToolSchema(
        z.object({
          publicToken: z.string().describe("Recipient's public key token (pqcv1.*.public.*)."),
          plaintext: z.string().optional().describe('Text to encrypt (UTF-8).'),
          plaintextBase64: z
            .string()
            .optional()
            .describe('Binary data to encrypt, base64-encoded.'),
        }),
      ),
    },
  ),
);

/**
 * Verify a ML-DSA signature.
 *
 * Returns `{ verified: true }` if the signature is genuine, or
 * `{ verified: false }` if tampered, wrong key, or wrong message.
 * Always verify before trusting a message from another agent.
 *
 * @example
 * ```ts
 * import { pqc } from '@pqc-sdk/core';
 * import { pqcVerifyTool } from '@pqc-sdk/langchain';
 *
 * const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
 * const signature = await pqc.sign('doc', signer.secretKey);
 * const result = await pqcVerifyTool.invoke({
 *   message: 'doc',
 *   signatureHex: Array.from(signature, (b) => b.toString(16).padStart(2, '0')).join(''),
 *   publicToken: pqc.keys.serialize(signer.publicKey),
 * });
 * // result → '{"verified":true}'
 * ```
 */
export const pqcVerifyTool: StructuredToolInterface = asStructuredTool(
  tool(
    (input: { message: string; signatureHex: string; publicToken: string }) =>
      run(async () => {
        const { message, signatureHex, publicToken } = input;
        const key = pqc.keys.deserialize(publicToken);
        let signature: Uint8Array;
        try {
          signature = hexToBytes(signatureHex);
        } catch {
          // A signature that is not even hex cannot be genuine.
          return JSON.stringify({ verified: false });
        }
        const verified = await (
          pqc.verify as (data: string, sig: Uint8Array, key: PqcKey) => Promise<boolean>
        )(message, signature, key);
        return JSON.stringify({ verified });
      }),
    {
      name: 'pqc_verify',
      description:
        'Verify a ML-DSA signature. Returns { verified: true } if genuine, ' +
        '{ verified: false } if tampered, wrong key, or wrong message. ' +
        'Always verify before trusting a message from another agent.',
      // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
      schema: asToolSchema(
        z.object({
          message: z.string().describe('Original message that was signed.'),
          signatureHex: z.string().describe('Hex-encoded signature from pqc_sign.'),
          publicToken: z.string().describe("Signer's ML-DSA public key token."),
        }),
      ),
    },
  ),
);

/**
 * List all supported algorithms.
 *
 * Call this before `pqc_keygen` to let the agent self-discover what is
 * available. The `fips` array contains only NIST-standardized algorithms;
 * `x-wing` (a CFRG draft) is in `supported` but not in `fips`.
 *
 * @example
 * ```ts
 * import { pqcAlgorithmsTool } from '@pqc-sdk/langchain';
 *
 * const result = await pqcAlgorithmsTool.invoke({});
 * // result → '{"supported":[…],"fips":[…]}'
 * ```
 */
export const pqcAlgorithmsTool: StructuredToolInterface = asStructuredTool(
  tool(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    (__args: { _noop?: string }) =>
      Promise.resolve(
        JSON.stringify({
          supported: [...SUPPORTED_ALGORITHMS],
          fips: [...FIPS_ALGORITHMS],
        }),
      ),
    {
      name: 'pqc_algorithms',
      description:
        'List all supported post-quantum algorithms and the FIPS-standardized subset. ' +
        'Use before pqc_keygen to choose the right algorithm for your security requirements.',
      // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
      schema: asToolSchema(z.object({ _noop: z.string().optional() })),
    },
  ),
);

// ─── Key-backed tools ─────────────────────────────────────────────────────────

/** Options for {@link createPqcTools}. */
export interface CreatePqcToolsOptions {
  /**
   * Returns the secret key stored under `keyId`. Called on every
   * `pqc_decrypt` / `pqc_sign`, with a `keyId` already checked against
   * {@link KEY_ID_PATTERN}. Throw if the key does not exist.
   */
  readonly resolveSecretKey: (keyId: string) => Promise<SecretKey>;
  /**
   * Receives each secret key generated by `pqc_keygen`; store it under
   * `keyId`. The tool returns the public key to the model only after this
   * resolves. If omitted, `pqc_keygen` is not included.
   */
  readonly onSecretKey?: (keyId: string, secretKey: SecretKey) => void | Promise<void>;
  /** Include `pqc_sign`. Default: `false`. */
  readonly enableSign?: boolean;
}

async function resolveKey(options: CreatePqcToolsOptions, keyId: string): Promise<SecretKey> {
  let key: unknown;
  try {
    key = await options.resolveSecretKey(requireKeyId(keyId));
  } catch (cause) {
    if (cause instanceof Error && cause.message.startsWith('PqcError[')) throw cause;
    // The application's error may carry storage details; keep them out of the
    // model context (they remain available as `cause` to the caller).
    throw Object.assign(
      toolError('KEY_NOT_FOUND', `No secret key could be resolved for keyId "${keyId}"`),
      { cause },
    );
  }
  if (typeof key !== 'object' || key === null || (key as Partial<PqcKey>).use !== 'secret') {
    throw toolError(
      'KEY_NOT_FOUND',
      `resolveSecretKey did not return a secret key for keyId "${keyId}"`,
    );
  }
  return key as SecretKey;
}

function keygenTool(
  onSecretKey: (keyId: string, secretKey: SecretKey) => void | Promise<void>,
): StructuredToolInterface {
  return asStructuredTool(
    tool(
      (input: { algorithm: AlgorithmInput }) =>
        run(async () => {
          const algorithm: Algorithm = input.algorithm;
          const pair = await pqc.keys.generate({ algorithm });
          const keyId = `${algorithm}-${bytesToHex(randomBytes(6))}`;
          try {
            await onSecretKey(keyId, pair.secretKey);
          } catch (cause) {
            throw Object.assign(
              toolError(
                'KEY_STORAGE_FAILED',
                'onSecretKey failed; the generated key was discarded',
              ),
              { cause },
            );
          }
          return JSON.stringify({
            keyId,
            algorithm,
            publicToken: pqc.keys.serialize(pair.publicKey),
          });
        }),
      {
        name: 'pqc_keygen',
        description:
          'Generate a post-quantum key pair. Returns its keyId and publicToken (safe to share); ' +
          'the secret key is stored by the application and never returned. ' +
          'Use x-wing or ml-kem-768 for encryption, ml-dsa-65 for signatures.',
        // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
        schema: asToolSchema(z.object({ algorithm: AlgorithmSchema })),
      },
    ),
  );
}

function decryptTool(options: CreatePqcToolsOptions): StructuredToolInterface {
  return asStructuredTool(
    tool(
      (input: { keyId: string; ciphertextHex: string }) =>
        run(async () => {
          let ciphertext: Uint8Array;
          try {
            ciphertext = hexToBytes(input.ciphertextHex);
          } catch {
            throw toolError('INVALID_CIPHERTEXT', 'ciphertextHex is not valid hex');
          }
          const key = await resolveKey(options, input.keyId);
          const pt = await (pqc.decrypt as (ct: Uint8Array, key: PqcKey) => Promise<Uint8Array>)(
            ciphertext,
            key,
          );
          return JSON.stringify(plaintextResult(pt));
        }),
      {
        name: 'pqc_decrypt',
        description:
          'Decrypt a ciphertext with a stored key, by keyId. Returns ' +
          '{ encoding: "utf8", plaintext } when the data is valid UTF-8, otherwise ' +
          '{ encoding: "base64", plaintextBase64 }. ' +
          'Throws PqcError[DECRYPTION_FAILED] if tampered, truncated, or wrong key.',
        // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
        schema: asToolSchema(
          z.object({
            keyId: KeyIdSchema,
            ciphertextHex: z.string().describe('Hex-encoded ciphertext from pqc_encrypt.'),
          }),
        ),
      },
    ),
  );
}

function signTool(options: CreatePqcToolsOptions): StructuredToolInterface {
  return asStructuredTool(
    tool(
      (input: { keyId: string; message: string }) =>
        run(async () => {
          const key = await resolveKey(options, input.keyId);
          const sig = await (pqc.sign as (data: string, key: PqcKey) => Promise<Uint8Array>)(
            input.message,
            key,
          );
          return JSON.stringify({ signatureHex: bytesToHex(sig) });
        }),
      {
        name: 'pqc_sign',
        description:
          'Sign a message with a stored ML-DSA key, by keyId. Returns a signatureHex that proves ' +
          'the message came from this key and was not modified. Quantum-resistant.',
        // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
        schema: asToolSchema(
          z.object({
            keyId: KeyIdSchema,
            message: z.string().describe('Message to sign (UTF-8).'),
          }),
        ),
      },
    ),
  );
}

/**
 * Builds the PQC tool set, wired to your secret-key storage.
 *
 * Secret keys never reach the model: `pqc_keygen` hands each new secret key
 * to `onSecretKey` and returns only `{ keyId, algorithm, publicToken }`;
 * `pqc_decrypt` and `pqc_sign` take a `keyId` and fetch the key through
 * `resolveSecretKey`. `pqc_keygen` is included only when `onSecretKey` is
 * given, and `pqc_sign` only when `enableSign` is `true`.
 *
 * @example
 * ```ts
 * import type { SecretKey } from '@pqc-sdk/core';
 * import { createPqcTools } from '@pqc-sdk/langchain';
 *
 * // Replace with your secrets manager; a Map is enough for a demo.
 * const vault = new Map<string, SecretKey>();
 *
 * const tools = createPqcTools({
 *   resolveSecretKey: async (keyId) => {
 *     const key = vault.get(keyId);
 *     if (!key) throw new Error(`unknown key ${keyId}`);
 *     return key;
 *   },
 *   onSecretKey: (keyId, secretKey) => {
 *     vault.set(keyId, secretKey);
 *   },
 * });
 * // Pass `tools` to createReactAgent, ToolNode, or any tool-aware component.
 * ```
 */
export function createPqcTools(options: CreatePqcToolsOptions): StructuredToolInterface[] {
  return [
    ...(options.onSecretKey ? [keygenTool(options.onSecretKey)] : []),
    pqcEncryptTool,
    decryptTool(options),
    ...(options.enableSign === true ? [signTool(options)] : []),
    pqcVerifyTool,
    pqcAlgorithmsTool,
  ];
}
