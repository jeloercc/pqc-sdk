/**
 * @pqc-sdk/mcp-server
 *
 * MCP (Model Context Protocol) server that exposes @pqc-sdk/core
 * post-quantum cryptographic operations as agent tools.
 *
 * Tools:
 *   pqc_keygen       — generate a key pair into the keystore; returns keyId + publicToken
 *   pqc_list_keys    — list the keystore's keys (keyId, algorithm, publicToken)
 *   pqc_encrypt      — encrypt text or binary data for a public key
 *   pqc_decrypt      — decrypt with a keystore key, by keyId
 *   pqc_sign         — sign with a keystore key, by keyId (only with PQC_MCP_ENABLE_SIGN=1)
 *   pqc_verify       — verify a signature
 *   pqc_algorithms   — list supported algorithms
 *
 * Stored secret keys are accessed by keyId and are not returned by key
 * management tools. Decrypted plaintext is returned to the model and may
 * itself contain secrets or untrusted instructions.
 *
 * Transport: stdio — compatible with Claude Desktop, Bob, Cursor, and any
 * MCP-capable host. stdout carries the protocol; all logs go to stderr.
 * Add to your host config:
 *
 *   {
 *     "mcpServers": {
 *       "pqc": {
 *         "command": "pqc-mcp",
 *         "env": { "PQC_KEYSTORE_DIR": "/path/to/a/dedicated/agent-keys", "PQC_MCP_MAX_KEYS": "100" }
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { handleTool } from './handlers.js';
import { FileKeyStore, KEY_ID_PATTERN } from './keystore.js';
import { listTools } from './tools.js';

declare const __PQC_MCP_VERSION__: string;
const VERSION: string = typeof __PQC_MCP_VERSION__ !== 'undefined' ? __PQC_MCP_VERSION__ : '0.1.0';

// ─── Configuration ────────────────────────────────────────────────────────────

function loadKeyStore(): FileKeyStore {
  try {
    return FileKeyStore.fromEnv(process.env);
  } catch (cause) {
    // Configuration errors stop the server instead of falling back silently.
    const message = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`pqc-mcp: invalid configuration: ${message}\n`);
    process.exit(1);
  }
}

const keyStore = loadKeyStore();
const enableSign = process.env['PQC_MCP_ENABLE_SIGN'] === '1';

function keyAllowlist(name: string): ReadonlySet<string> | undefined {
  const raw = process.env[name];
  if (raw === undefined) return undefined;
  if (raw.trim() === '') return new Set();
  const ids = raw.split(',').map((value) => value.trim());
  if (ids.some((id) => !KEY_ID_PATTERN.test(id))) {
    throw new Error(`${name} must contain comma-separated valid key IDs`);
  }
  return new Set(ids);
}

let decryptKeyIds: ReadonlySet<string> | undefined;
let signKeyIds: ReadonlySet<string> | undefined;
try {
  decryptKeyIds = keyAllowlist('PQC_MCP_DECRYPT_KEY_IDS');
  signKeyIds = keyAllowlist('PQC_MCP_SIGN_KEY_IDS');
} catch (cause) {
  process.stderr.write(
    `pqc-mcp: invalid configuration: ${cause instanceof Error ? cause.message : 'invalid key allowlist'}\n`,
  );
  process.exit(1);
}

process.stderr.write(
  `pqc-mcp ${VERSION}: keystore ${keyStore.directory} (max ${keyStore.maxKeys} keys); pqc_sign ${enableSign ? 'enabled' : 'disabled'}\n`,
);

// ─── Server setup ─────────────────────────────────────────────────────────────

const server = new Server({ name: 'pqc-sdk', version: VERSION }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: listTools({ enableSign }) }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const safeArgs: Record<string, unknown> = args ?? {};
  return handleTool(name, safeArgs, {
    keyStore,
    enableSign,
    ...(decryptKeyIds && { decryptKeyIds }),
    ...(signKeyIds && { signKeyIds }),
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

// Bound the raw JSON-RPC buffer before parsing or dispatching tool calls.
const transport = new StdioServerTransport(process.stdin, process.stdout, {
  maxBufferSize: 10 * 1024 * 1024,
});
await server.connect(transport);
