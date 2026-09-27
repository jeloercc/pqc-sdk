/**
 * End-to-end over the real stdio transport: spawns the built server
 * (dist/index.js — `pnpm test` builds first), checks that logs stay on
 * stderr, and that keys survive a server restart.
 */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const SERVER = fileURLToPath(new URL('../dist/index.js', import.meta.url));

let keyDir: string;
let clients: Client[];

beforeEach(async () => {
  keyDir = await mkdtemp(join(tmpdir(), 'pqc-mcp-stdio-'));
  clients = [];
});

afterEach(async () => {
  await Promise.all(clients.map((client) => client.close()));
  await rm(keyDir, { recursive: true, force: true });
});

async function start(
  env: Record<string, string> = {},
): Promise<{ client: Client; stderr: () => string }> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { PATH: process.env['PATH'] ?? '', PQC_KEYSTORE_DIR: keyDir, ...env },
    stderr: 'pipe',
  });
  let stderr = '';
  transport.stderr?.on('data', (chunk: Buffer) => {
    stderr += chunk.toString('utf8');
  });
  const client = new Client({ name: 'pqc-mcp-test', version: '0' });
  await client.connect(transport);
  clients.push(client);
  return { client, stderr: () => stderr };
}

async function callJson(client: Client, name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const content = result.content as { type: string; text: string }[];
  return JSON.parse(content[0]?.text ?? 'null') as Record<string, unknown>;
}

describe('stdio server', () => {
  it('logs its configuration to stderr and hides pqc_sign by default', async () => {
    const { client, stderr } = await start();
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name)).not.toContain('pqc_sign');
    expect(tools.map((tool) => tool.name)).toContain('pqc_list_keys');
    expect(stderr()).toContain(`keystore ${keyDir}`);
    expect(stderr()).toContain('pqc_sign disabled');
  });

  it('exposes pqc_sign when PQC_MCP_ENABLE_SIGN=1', async () => {
    const { client } = await start({ PQC_MCP_ENABLE_SIGN: '1' });
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name)).toContain('pqc_sign');
  });

  it('decrypts with a key generated before a server restart', async () => {
    const first = await start();
    const { keyId, publicToken } = await callJson(first.client, 'pqc_keygen');
    const { ciphertextHex } = await callJson(first.client, 'pqc_encrypt', {
      publicToken,
      plaintext: 'across restarts',
    });
    await first.client.close();

    const second = await start();
    expect(await callJson(second.client, 'pqc_decrypt', { keyId, ciphertextHex })).toEqual({
      encoding: 'utf8',
      plaintext: 'across restarts',
    });
  }, 30_000);
});
