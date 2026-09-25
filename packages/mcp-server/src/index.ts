/**
 * @pqc-sdk/mcp-server
 *
 * MCP (Model Context Protocol) server that exposes @pqc-sdk/core
 * post-quantum cryptographic operations as agent tools.
 *
 * Tools:
 *   pqc_keygen       — generate a key pair
 *   pqc_encrypt      — encrypt a message
 *   pqc_decrypt      — decrypt a ciphertext
 *   pqc_sign         — sign a message
 *   pqc_verify       — verify a signature
 *   pqc_algorithms   — list supported algorithms
 *
 * Transport: stdio — compatible with Claude Desktop, Bob, Cursor, and any
 * MCP-capable host. Add to your host config:
 *
 *   {
 *     "mcpServers": {
 *       "pqc": {
 *         "command": "node",
 *         "args": ["node_modules/@pqc-sdk/mcp-server/dist/index.js"]
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { handleToolForTest } from './handlers.js';

declare const __PQC_MCP_VERSION__: string;
const VERSION: string = typeof __PQC_MCP_VERSION__ !== 'undefined' ? __PQC_MCP_VERSION__ : '0.1.0';

// ─── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'pqc_keygen',
    description:
      'Generate a post-quantum key pair. Returns publicToken (safe to share) and secretToken ' +
      '(keep secret — never include in responses or conversation history). ' +
      'Use ml-kem-768 or x-wing for encryption, ml-dsa-65 for signatures.',
    inputSchema: {
      type: 'object',
      properties: {
        algorithm: {
          type: 'string',
          enum: [
            'ml-kem-512',
            'ml-kem-768',
            'ml-kem-1024',
            'x-wing',
            'ml-dsa-44',
            'ml-dsa-65',
            'ml-dsa-87',
          ],
          description: 'Algorithm to use. Default: x-wing.',
          default: 'x-wing',
        },
      },
      required: [],
    },
  },
  {
    name: 'pqc_encrypt',
    description:
      'Encrypt a message for a recipient using their public key token. ' +
      'Only the holder of the matching secret key can decrypt. Quantum-resistant.',
    inputSchema: {
      type: 'object',
      properties: {
        plaintext: { type: 'string', description: 'Message to encrypt (UTF-8).' },
        publicToken: {
          type: 'string',
          description: "Recipient's public key token (pqcv1.*.public.*).",
        },
      },
      required: ['plaintext', 'publicToken'],
    },
  },
  {
    name: 'pqc_decrypt',
    description:
      'Decrypt a ciphertext using a secret key token. ' +
      'Returns isError with DECRYPTION_FAILED if tampered or wrong key.',
    inputSchema: {
      type: 'object',
      properties: {
        ciphertextHex: { type: 'string', description: 'Hex-encoded ciphertext from pqc_encrypt.' },
        secretToken: { type: 'string', description: 'Secret key token (pqcv1.*.secret.*).' },
      },
      required: ['ciphertextHex', 'secretToken'],
    },
  },
  {
    name: 'pqc_sign',
    description:
      'Sign a message with a ML-DSA secret key. ' +
      'Proves the message came from this key and was not modified.',
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string', description: 'Message to sign (UTF-8).' },
        secretToken: {
          type: 'string',
          description: 'ML-DSA secret key token (pqcv1.ml-dsa-*.secret.*).',
        },
      },
      required: ['message', 'secretToken'],
    },
  },
  {
    name: 'pqc_verify',
    description:
      'Verify a ML-DSA signature. Returns { verified: true } if genuine, ' +
      '{ verified: false } if tampered, wrong key, or wrong message.',
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string', description: 'Original message that was signed.' },
        signatureHex: { type: 'string', description: 'Hex-encoded signature from pqc_sign.' },
        publicToken: { type: 'string', description: "Signer's ML-DSA public key token." },
      },
      required: ['message', 'signatureHex', 'publicToken'],
    },
  },
  {
    name: 'pqc_algorithms',
    description:
      'List all supported algorithms and the FIPS-standardized subset. ' +
      'Use this before pqc_keygen to pick the right algorithm.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
] as const;

// ─── Server setup ─────────────────────────────────────────────────────────────

const server = new Server({ name: 'pqc-sdk', version: VERSION }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const safeArgs: Record<string, unknown> = args ?? {};
  return handleToolForTest(name, safeArgs);
});

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
