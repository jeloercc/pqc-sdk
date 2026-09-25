/**
 * Tool handler logic — extracted from index.ts so tests can import and
 * call handlers directly without starting the MCP stdio transport.
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { FIPS_ALGORITHMS, PqcError, SUPPORTED_ALGORITHMS, pqc } from '@pqc-sdk/core';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

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

// ─── Handler ─────────────────────────────────────────────────────────────────

export async function handleToolForTest(
  name: string,
  args: Record<string, unknown> = {},
): Promise<CallToolResult> {
  try {
    switch (name) {
      case 'pqc_keygen': {
        const algorithm = (args['algorithm'] as string | undefined) ?? 'x-wing';
        // The generate overload is generic over Algorithm — cast to a looser
        // signature so we can pass an arbitrary string and let the SDK's own
        // runtime check (getAlgorithm) surface UNSUPPORTED_ALGORITHM.
        const pair = await (
          pqc.keys.generate as (opts: { algorithm: string }) => Promise<{
            publicKey: Parameters<typeof pqc.keys.serialize>[0];
            secretKey: Parameters<typeof pqc.keys.serialize>[0];
          }>
        )({ algorithm });
        return ok({
          algorithm,
          publicToken: pqc.keys.serialize(pair.publicKey),
          secretToken: pqc.keys.serialize(pair.secretKey),
          warning: 'Store secretToken securely. Never include it in agent responses.',
        });
      }

      case 'pqc_encrypt': {
        const { plaintext, publicToken } = args as { plaintext: string; publicToken: string };
        const key = pqc.keys.deserialize(publicToken);
        // deserialize returns PqcKey<Algorithm, KeyUse>; encrypt accepts
        // PublicKey<KemAlgorithm>. The runtime requireKey check inside encrypt
        // handles wrong-algorithm errors (e.g. passing a DSA key here).
        const ct = await (pqc.encrypt as (data: string, key: unknown) => Promise<Uint8Array>)(
          plaintext,
          key,
        );
        return ok({ ciphertextHex: bytesToHex(ct) });
      }

      case 'pqc_decrypt': {
        const { ciphertextHex, secretToken } = args as {
          ciphertextHex: string;
          secretToken: string;
        };
        const key = pqc.keys.deserialize(secretToken);
        const pt = await (pqc.decrypt as (ct: Uint8Array, key: unknown) => Promise<Uint8Array>)(
          hexToBytes(ciphertextHex),
          key,
        );
        return ok({ plaintext: new TextDecoder().decode(pt) });
      }

      case 'pqc_sign': {
        const { message, secretToken } = args as { message: string; secretToken: string };
        const key = pqc.keys.deserialize(secretToken);
        const sig = await (pqc.sign as (data: string, key: unknown) => Promise<Uint8Array>)(
          message,
          key,
        );
        return ok({ signatureHex: bytesToHex(sig) });
      }

      case 'pqc_verify': {
        const { message, signatureHex, publicToken } = args as {
          message: string;
          signatureHex: string;
          publicToken: string;
        };
        const key = pqc.keys.deserialize(publicToken);
        const verified = await (
          pqc.verify as (data: string, sig: Uint8Array, key: unknown) => Promise<boolean>
        )(message, hexToBytes(signatureHex), key);
        return ok({ verified });
      }

      case 'pqc_algorithms': {
        return ok({ supported: [...SUPPORTED_ALGORITHMS], fips: [...FIPS_ALGORITHMS] });
      }

      default:
        return fail('UNKNOWN_TOOL', `Unknown tool: ${name}`);
    }
  } catch (cause) {
    if (cause instanceof PqcError) {
      return fail(cause.code, cause.message);
    }
    const message = cause instanceof Error ? cause.message : String(cause);
    return fail('INTERNAL_ERROR', message);
  }
}
