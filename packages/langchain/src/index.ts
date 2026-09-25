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
 *   pqcKeygenTool     — generate a key pair
 *   pqcEncryptTool    — encrypt a message
 *   pqcDecryptTool    — decrypt a ciphertext
 *   pqcSignTool       — sign a message (ML-DSA)
 *   pqcVerifyTool     — verify a signature
 *   pqcAlgorithmsTool — list supported algorithms
 *   pqcTools          — all six tools as a readonly array
 *
 * Security contract:
 *   - secretToken is NEVER returned by any tool output intended for the agent
 *     to relay to users. pqcKeygenTool does return it so the calling agent can
 *     store it — the agent must not forward it onward.
 *   - All PqcError codes propagate as thrown errors with a structured
 *     `PqcError[CODE]: message` prefix so the agent's error handler can branch.
 */

import { tool } from '@langchain/core/tools';
import { FIPS_ALGORITHMS, PqcError, SUPPORTED_ALGORITHMS, pqc } from '@pqc-sdk/core';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
// @langchain/core expects Zod v3 schemas. Import from the v3 compatibility
// subpath so the types align even when the root project installs Zod v4.
// The `as unknown as ToolSchema` cast on each schema below bridges the remaining
// _def.description strictness gap between langchain's internal types and zod/v3
// — it is scoped to the schema argument and has no runtime effect.
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
// mismatch at precisely the call site that needs it.
function asToolSchema<T>(schema: T): unknown {
  return schema;
}

// ─── Shared algorithm enum ────────────────────────────────────────────────────

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
    'Algorithm to use. For encryption: ml-kem-768 (recommended, FIPS 203 cat.3), ' +
      'ml-kem-512 (lighter, cat.1), ml-kem-1024 (strongest, cat.5), x-wing (PQ+classical hybrid). ' +
      'For signatures: ml-dsa-65 (recommended, FIPS 204 cat.3).',
  );

type AlgorithmInput = z.infer<typeof AlgorithmSchema>;

// ─── Wrapper to surface PqcError codes to the agent ──────────────────────────

async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (cause) {
    if (cause instanceof PqcError) {
      throw new Error(`PqcError[${cause.code}]: ${cause.message}`);
    }
    throw cause;
  }
}

// ─── pqcKeygenTool ────────────────────────────────────────────────────────────

/**
 * Generate a post-quantum key pair.
 *
 * Returns `publicToken` (safe to share) and `secretToken` (must be stored
 * securely by the agent — never included in user-facing responses).
 */
export const pqcKeygenTool = tool(
  (input: { algorithm: AlgorithmInput }) =>
    run(async () => {
      const { algorithm } = input;
      const pair = await (
        pqc.keys.generate as (opts: { algorithm: string }) => Promise<{
          publicKey: Parameters<typeof pqc.keys.serialize>[0];
          secretKey: Parameters<typeof pqc.keys.serialize>[0];
        }>
      )({ algorithm });
      return JSON.stringify({
        algorithm,
        publicToken: pqc.keys.serialize(pair.publicKey),
        secretToken: pqc.keys.serialize(pair.secretKey),
        warning:
          'Store secretToken securely. Never forward it to users or include it in responses.',
      });
    }),
  {
    name: 'pqc_keygen',
    description:
      'Generate a post-quantum cryptographic key pair. Returns publicToken (shareable) and ' +
      'secretToken (keep secret — store in agent memory, never relay to users or conversations). ' +
      'Use ml-kem-768 or x-wing for encryption/decryption. Use ml-dsa-65 for signatures.',
    // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
    schema: asToolSchema(z.object({ algorithm: AlgorithmSchema })),
  },
);

// ─── pqcEncryptTool ───────────────────────────────────────────────────────────

/**
 * Encrypt a message for a recipient.
 *
 * The result (`ciphertextHex`) can only be decrypted by the holder of the
 * matching secret key. Safe to transmit over any channel.
 */
export const pqcEncryptTool = tool(
  (input: { plaintext: string; publicToken: string }) =>
    run(async () => {
      const { plaintext, publicToken } = input;
      const key = pqc.keys.deserialize(publicToken);
      const ct = await (pqc.encrypt as (data: string, key: unknown) => Promise<Uint8Array>)(
        plaintext,
        key,
      );
      return JSON.stringify({ ciphertextHex: bytesToHex(ct) });
    }),
  {
    name: 'pqc_encrypt',
    description:
      'Encrypt a message for a recipient using their public key token. ' +
      'Only the holder of the matching secret key can decrypt. Quantum-resistant.',
    // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
    schema: asToolSchema(
      z.object({
        plaintext: z.string().describe('Message to encrypt (UTF-8).'),
        publicToken: z.string().describe("Recipient's public key token (pqcv1.*.public.*)."),
      }),
    ),
  },
);

// ─── pqcDecryptTool ───────────────────────────────────────────────────────────

/**
 * Decrypt a ciphertext using a secret key.
 *
 * Throws if the ciphertext is tampered, truncated, or was not encrypted for
 * this key. The error includes a structured `PqcError[DECRYPTION_FAILED]`
 * prefix so the agent's error handler can branch on it.
 */
export const pqcDecryptTool = tool(
  (input: { ciphertextHex: string; secretToken: string }) =>
    run(async () => {
      const { ciphertextHex, secretToken } = input;
      const key = pqc.keys.deserialize(secretToken);
      const pt = await (pqc.decrypt as (ct: Uint8Array, key: unknown) => Promise<Uint8Array>)(
        hexToBytes(ciphertextHex),
        key,
      );
      return JSON.stringify({ plaintext: new TextDecoder().decode(pt) });
    }),
  {
    name: 'pqc_decrypt',
    description:
      'Decrypt a ciphertext using a secret key token. ' +
      'Throws PqcError[DECRYPTION_FAILED] if tampered, truncated, or wrong key.',
    // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
    schema: asToolSchema(
      z.object({
        ciphertextHex: z.string().describe('Hex-encoded ciphertext from pqc_encrypt.'),
        secretToken: z.string().describe('Secret key token (pqcv1.*.secret.*).'),
      }),
    ),
  },
);

// ─── pqcSignTool ──────────────────────────────────────────────────────────────

/**
 * Sign a message with a ML-DSA secret key.
 *
 * The `signatureHex` proves the message came from the holder of this key and
 * was not modified. Attach it to the message when forwarding to other agents.
 */
export const pqcSignTool = tool(
  (input: { message: string; secretToken: string }) =>
    run(async () => {
      const { message, secretToken } = input;
      const key = pqc.keys.deserialize(secretToken);
      const sig = await (pqc.sign as (data: string, key: unknown) => Promise<Uint8Array>)(
        message,
        key,
      );
      return JSON.stringify({ signatureHex: bytesToHex(sig) });
    }),
  {
    name: 'pqc_sign',
    description:
      'Sign a message with a ML-DSA secret key. Returns a signatureHex that proves ' +
      'the message came from this key and was not modified. Quantum-resistant.',
    // @ts-expect-error — ZodV3ObjectLike ._def.description type mismatch (langchain/core interop)
    schema: asToolSchema(
      z.object({
        message: z.string().describe('Message to sign (UTF-8).'),
        secretToken: z.string().describe('ML-DSA secret key token (pqcv1.ml-dsa-*.secret.*).'),
      }),
    ),
  },
);

// ─── pqcVerifyTool ────────────────────────────────────────────────────────────

/**
 * Verify a ML-DSA signature.
 *
 * Returns `{ verified: true }` if the signature is genuine, or
 * `{ verified: false }` if tampered, wrong key, or wrong message.
 * Always verify before trusting a message from another agent.
 */
export const pqcVerifyTool = tool(
  (input: { message: string; signatureHex: string; publicToken: string }) =>
    run(async () => {
      const { message, signatureHex, publicToken } = input;
      const key = pqc.keys.deserialize(publicToken);
      const verified = await (
        pqc.verify as (data: string, sig: Uint8Array, key: unknown) => Promise<boolean>
      )(message, hexToBytes(signatureHex), key);
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
);

// ─── pqcAlgorithmsTool ────────────────────────────────────────────────────────

/**
 * List all supported algorithms.
 *
 * Call this before `pqc_keygen` to let the agent self-discover what is
 * available. The `fips` array contains only NIST-standardized algorithms;
 * `x-wing` (a CFRG draft) is in `supported` but not in `fips`.
 */
export const pqcAlgorithmsTool = tool(
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
);

// ─── Convenience bundle ───────────────────────────────────────────────────────

/**
 * All six PQC tools as a readonly array.
 *
 * Pass directly to `createReactAgent`, `ToolNode`, or any tool-aware
 * LangChain / LangGraph component.
 *
 * @example
 * ```ts
 * import { createReactAgent } from '@langchain/langgraph/prebuilt';
 * import { ChatAnthropic } from '@langchain/anthropic';
 * import { pqcTools } from '@pqc-sdk/langchain';
 *
 * const agent = createReactAgent({
 *   llm: new ChatAnthropic({ model: 'claude-opus-4-5' }),
 *   tools: [...pqcTools],
 * });
 * ```
 */
export const pqcTools = [
  pqcKeygenTool,
  pqcEncryptTool,
  pqcDecryptTool,
  pqcSignTool,
  pqcVerifyTool,
  pqcAlgorithmsTool,
] as const;
