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
 * Secret keys never pass through the model context: they live in the keystore
 * directory (PQC_KEYSTORE_DIR, or a per-user default) and tools refer to them
 * only by keyId.
 *
 * Transport: stdio — compatible with Claude Desktop, Bob, Cursor, and any
 * MCP-capable host. stdout carries the protocol; all logs go to stderr.
 * Add to your host config:
 *
 *   {
 *     "mcpServers": {
 *       "pqc": {
 *         "command": "pqc-mcp",
 *         "env": { "PQC_KEYSTORE_DIR": "/path/to/a/dedicated/agent-keys" }
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { handleTool } from './handlers.js';
import { FileKeyStore } from './keystore.js';
import { listTools } from './tools.js';

declare const __PQC_MCP_VERSION__: string;
const VERSION: string = typeof __PQC_MCP_VERSION__ !== 'undefined' ? __PQC_MCP_VERSION__ : '0.1.0';

// ─── Configuration ────────────────────────────────────────────────────────────

const keyStore = FileKeyStore.fromEnv(process.env);
const enableSign = process.env['PQC_MCP_ENABLE_SIGN'] === '1';

process.stderr.write(
  `pqc-mcp ${VERSION}: keystore ${keyStore.directory}; pqc_sign ${enableSign ? 'enabled' : 'disabled'}\n`,
);

// ─── Server setup ─────────────────────────────────────────────────────────────

const server = new Server({ name: 'pqc-sdk', version: VERSION }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: listTools({ enableSign }) }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const safeArgs: Record<string, unknown> = args ?? {};
  return handleTool(name, safeArgs, { keyStore, enableSign });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
