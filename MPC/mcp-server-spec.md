# MCP Server Design — `@pqc-sdk/mcp-server`

> Model Context Protocol server exposing all PQC operations as tools.
> Compatible with Claude Desktop, Cursor, Bob, and any MCP-capable host.

---

## Transport

| Mode    | Use case                                        |
| ------- | ----------------------------------------------- |
| `stdio` | Local agent hosts (Claude Desktop, Bob, Cursor) |
| `SSE`   | Remote / cloud agents over HTTP                 |

---

## Tool registration

```typescript
// packages/mcp-server/src/index.ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { pqc, SUPPORTED_ALGORITHMS, FIPS_ALGORITHMS } from '@pqc-sdk/core';
import { hexToBytes } from '@noble/hashes/utils.js';

const server = new Server({ name: 'pqc-sdk', version: '1.0.0' }, { capabilities: { tools: {} } });

// ── pqc_keygen ─────────────────────────────────────────────────────────────
server.registerTool('pqc_keygen', {
  description: 'Generate a post-quantum key pair.',
  inputSchema: {
    type: 'object',
    properties: {
      algorithm: { type: 'string', default: 'x-wing' },
    },
  },
  handler: async ({ algorithm = 'x-wing' }) => {
    const pair = await pqc.keys.generate({ algorithm });
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            publicToken: pqc.keys.serialize(pair.publicKey),
            secretToken: pqc.keys.serialize(pair.secretKey),
            algorithm,
          }),
        },
      ],
    };
  },
});

// ── pqc_encrypt ────────────────────────────────────────────────────────────
server.registerTool('pqc_encrypt', {
  description: 'Encrypt a message for a recipient.',
  inputSchema: {
    type: 'object',
    properties: {
      plaintext: { type: 'string' },
      publicToken: { type: 'string' },
    },
    required: ['plaintext', 'publicToken'],
  },
  handler: async ({ plaintext, publicToken }) => {
    const key = pqc.keys.deserialize(publicToken);
    const ct = await pqc.encrypt(plaintext, key);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ ciphertextHex: Buffer.from(ct).toString('hex') }),
        },
      ],
    };
  },
});

// ── pqc_decrypt ────────────────────────────────────────────────────────────
server.registerTool('pqc_decrypt', {
  description: 'Decrypt a ciphertext.',
  inputSchema: {
    type: 'object',
    properties: {
      ciphertextHex: { type: 'string' },
      secretToken: { type: 'string' },
    },
    required: ['ciphertextHex', 'secretToken'],
  },
  handler: async ({ ciphertextHex, secretToken }) => {
    const key = pqc.keys.deserialize(secretToken);
    const pt = await pqc.decrypt(hexToBytes(ciphertextHex), key);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ plaintext: new TextDecoder().decode(pt) }),
        },
      ],
    };
  },
});

// ── pqc_sign ───────────────────────────────────────────────────────────────
server.registerTool('pqc_sign', {
  description: 'Sign a message.',
  inputSchema: {
    type: 'object',
    properties: {
      message: { type: 'string' },
      secretToken: { type: 'string' },
    },
    required: ['message', 'secretToken'],
  },
  handler: async ({ message, secretToken }) => {
    const key = pqc.keys.deserialize(secretToken);
    const sig = await pqc.sign(message, key);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ signatureHex: Buffer.from(sig).toString('hex') }),
        },
      ],
    };
  },
});

// ── pqc_verify ─────────────────────────────────────────────────────────────
server.registerTool('pqc_verify', {
  description: 'Verify a signature.',
  inputSchema: {
    type: 'object',
    properties: {
      message: { type: 'string' },
      signatureHex: { type: 'string' },
      publicToken: { type: 'string' },
    },
    required: ['message', 'signatureHex', 'publicToken'],
  },
  handler: async ({ message, signatureHex, publicToken }) => {
    const key = pqc.keys.deserialize(publicToken);
    const verified = await pqc.verify(message, hexToBytes(signatureHex), key);
    return {
      content: [{ type: 'text', text: JSON.stringify({ verified }) }],
    };
  },
});

// ── pqc_algorithms ─────────────────────────────────────────────────────────
server.registerTool('pqc_algorithms', {
  description: 'List supported algorithms.',
  inputSchema: { type: 'object', properties: {} },
  handler: async () => ({
    content: [
      {
        type: 'text',
        text: JSON.stringify({ supported: SUPPORTED_ALGORITHMS, fips: FIPS_ALGORITHMS }),
      },
    ],
  }),
});

// ── start ──────────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
```

---

## Installation in a host (example: Bob / Claude Desktop)

```json
// .mcp/config.json
{
  "mcpServers": {
    "pqc": {
      "command": "node",
      "args": ["node_modules/@pqc-sdk/mcp-server/dist/index.js"],
      "transport": "stdio"
    }
  }
}
```

---

## Security constraints

1. **No state** — each tool call is fully stateless; no keys stored server-side.
2. **No logging of secret tokens** — if the host logs tool inputs, secret tokens
   are visible. Advise hosts to redact `secretToken` fields.
3. **Error mapping** — every `PqcError` is returned as `isError: true` with
   the `PqcErrorCode` in the message, so the agent can branch on it.
4. **Rate limiting** — production deployments should limit `pqc_keygen` calls
   per session to prevent entropy exhaustion on resource-constrained hosts.

---

## Package scaffold

```
packages/mcp-server/
  src/
    index.ts          ← server entry (code above)
  package.json        ← name: @pqc-sdk/mcp-server
  tsup.config.ts      ← bundle to dist/index.js (CJS + ESM)
  tsconfig.json
```

`package.json` dependencies:

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "@pqc-sdk/core": "workspace:*",
    "@noble/hashes": "^1.6.0"
  }
}
```
