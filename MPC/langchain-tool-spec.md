# LangChain / LangGraph Tool Wrappers — `@pqc-sdk/langchain`

> Drop-in Zod-typed tools for LangChain agents, LangGraph nodes, and any
> framework built on `@langchain/core`.

---

## Installation

```bash
npm install @pqc-sdk/langchain @pqc-sdk/core @langchain/core zod
```

---

## Complete implementation

```typescript
// packages/langchain/src/index.ts
import { tool } from '@langchain/core/tools';
import { pqc, SUPPORTED_ALGORITHMS, FIPS_ALGORITHMS } from '@pqc-sdk/core';
import { hexToBytes } from '@noble/hashes/utils.js';
import { z } from 'zod';

// ── pqcKeygenTool ──────────────────────────────────────────────────────────
export const pqcKeygenTool = tool(
  async ({ algorithm }) => {
    const pair = await pqc.keys.generate({ algorithm: algorithm as any });
    return JSON.stringify({
      publicToken: pqc.keys.serialize(pair.publicKey),
      secretToken: pqc.keys.serialize(pair.secretKey),
      algorithm,
    });
  },
  {
    name: 'pqc_keygen',
    description:
      'Generate a post-quantum key pair. Use ml-kem-768 or x-wing for encryption, ' +
      'ml-dsa-65 for signatures. Returns publicToken (shareable) and secretToken ' +
      '(store securely — never expose in responses).',
    schema: z.object({
      algorithm: z
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
        .describe('Algorithm to use.'),
    }),
  },
);

// ── pqcEncryptTool ─────────────────────────────────────────────────────────
export const pqcEncryptTool = tool(
  async ({ plaintext, publicToken }) => {
    const key = pqc.keys.deserialize(publicToken);
    const ct = await pqc.encrypt(plaintext, key);
    return JSON.stringify({ ciphertextHex: Buffer.from(ct).toString('hex') });
  },
  {
    name: 'pqc_encrypt',
    description: 'Encrypt a message for a recipient using their public key token.',
    schema: z.object({
      plaintext: z.string().describe('Message to encrypt (UTF-8).'),
      publicToken: z.string().describe("Recipient's public key token (pqcv1.*.public.*)."),
    }),
  },
);

// ── pqcDecryptTool ─────────────────────────────────────────────────────────
export const pqcDecryptTool = tool(
  async ({ ciphertextHex, secretToken }) => {
    const key = pqc.keys.deserialize(secretToken);
    const pt = await pqc.decrypt(hexToBytes(ciphertextHex), key);
    return JSON.stringify({ plaintext: new TextDecoder().decode(pt) });
  },
  {
    name: 'pqc_decrypt',
    description: 'Decrypt a ciphertext using a secret key token.',
    schema: z.object({
      ciphertextHex: z.string().describe('Hex-encoded ciphertext from pqc_encrypt.'),
      secretToken: z.string().describe('Secret key token (pqcv1.*.secret.*).'),
    }),
  },
);

// ── pqcSignTool ────────────────────────────────────────────────────────────
export const pqcSignTool = tool(
  async ({ message, secretToken }) => {
    const key = pqc.keys.deserialize(secretToken);
    const sig = await pqc.sign(message, key);
    return JSON.stringify({ signatureHex: Buffer.from(sig).toString('hex') });
  },
  {
    name: 'pqc_sign',
    description: 'Sign a message with a ML-DSA secret key.',
    schema: z.object({
      message: z.string().describe('Message to sign.'),
      secretToken: z.string().describe('ML-DSA secret key token.'),
    }),
  },
);

// ── pqcVerifyTool ──────────────────────────────────────────────────────────
export const pqcVerifyTool = tool(
  async ({ message, signatureHex, publicToken }) => {
    const key = pqc.keys.deserialize(publicToken);
    const verified = await pqc.verify(message, hexToBytes(signatureHex), key);
    return JSON.stringify({ verified });
  },
  {
    name: 'pqc_verify',
    description: 'Verify a ML-DSA signature. Returns { verified: boolean }.',
    schema: z.object({
      message: z.string().describe('Original message.'),
      signatureHex: z.string().describe('Hex-encoded signature from pqc_sign.'),
      publicToken: z.string().describe("Signer's ML-DSA public key token."),
    }),
  },
);

// ── pqcAlgorithmsTool ──────────────────────────────────────────────────────
export const pqcAlgorithmsTool = tool(
  async () => JSON.stringify({ supported: SUPPORTED_ALGORITHMS, fips: FIPS_ALGORITHMS }),
  {
    name: 'pqc_algorithms',
    description: 'List all supported algorithms and the FIPS-standardized subset.',
    schema: z.object({}),
  },
);

/** All six tools as an array — pass directly to createReactAgent or a graph node. */
export const pqcTools = [
  pqcKeygenTool,
  pqcEncryptTool,
  pqcDecryptTool,
  pqcSignTool,
  pqcVerifyTool,
  pqcAlgorithmsTool,
] as const;
```

---

## Usage with a ReAct agent

```typescript
import { createReactAgent } from '@langchain/langgraph/prebuilt';
import { ChatAnthropic } from '@langchain/anthropic';
import { pqcTools } from '@pqc-sdk/langchain';

const agent = createReactAgent({
  llm: new ChatAnthropic({ model: 'claude-opus-4-5' }),
  tools: [...pqcTools],
});

const result = await agent.invoke({
  messages: [{ role: 'user', content: 'Generate a key pair and encrypt "hello agent" for me.' }],
});
```

---

## Usage in a LangGraph node

```typescript
import { StateGraph, MessagesAnnotation } from '@langchain/langgraph';
import { ToolNode } from '@langchain/langgraph/prebuilt';
import { pqcTools } from '@pqc-sdk/langchain';

const toolNode = new ToolNode(pqcTools);

const graph = new StateGraph(MessagesAnnotation)
  .addNode('crypto', toolNode)
  // ... rest of graph
  .compile();
```

---

## Package scaffold

```
packages/langchain/
  src/
    index.ts        ← all tools + pqcTools array
  package.json      ← name: @pqc-sdk/langchain
  tsup.config.ts
  tsconfig.json
```

`package.json` peer dependencies:

```json
{
  "peerDependencies": {
    "@langchain/core": ">=0.3.0",
    "@pqc-sdk/core": "workspace:*",
    "zod": ">=3.0.0"
  }
}
```
