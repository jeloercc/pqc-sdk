# LangChain / LangGraph Tool Wrappers — `@pqc-sdk/langchain`

> Zod-typed tools for LangChain agents, LangGraph nodes, and any framework
> built on `@langchain/core`.

---

## Core rule: secret keys never pass through the model context

No tool accepts or returns secret key material. Tools refer to secret keys by
`keyId`; the keys themselves move only through two callbacks the application
provides. The package performs no I/O — where keys are stored (a secrets
manager, a KMS-wrapped database, an encrypted file) is the application's
decision.

---

## Installation

```bash
npm install @pqc-sdk/langchain @pqc-sdk/core @langchain/core zod
```

---

## API

Implementation: `packages/langchain/src/index.ts`.

```typescript
interface CreatePqcToolsOptions {
  /** Returns the secret key stored under keyId (called on every decrypt/sign). */
  resolveSecretKey: (keyId: string) => Promise<SecretKey>;
  /** Receives each generated secret key. If omitted, pqc_keygen is not included. */
  onSecretKey?: (keyId: string, secretKey: SecretKey) => void | Promise<void>;
  /** Include pqc_sign. Default: false. */
  enableSign?: boolean;
}

function createPqcTools(options: CreatePqcToolsOptions): StructuredToolInterface[];

// Stateless tools, also included by createPqcTools:
const pqcEncryptTool: StructuredToolInterface;
const pqcVerifyTool: StructuredToolInterface;
const pqcAlgorithmsTool: StructuredToolInterface;
const KEY_ID_PATTERN: RegExp; // /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
```

| Tool             | Input                                                          | Output                                                                         |
| ---------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `pqc_keygen`     | `algorithm` (default `x-wing`) — only with `onSecretKey`       | `{ keyId, algorithm, publicToken }`                                            |
| `pqc_encrypt`    | `publicToken` + exactly one of `plaintext` / `plaintextBase64` | `{ ciphertextHex }`                                                            |
| `pqc_decrypt`    | `keyId`, `ciphertextHex`                                       | `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }` |
| `pqc_sign`       | `keyId`, `message` — only with `enableSign: true`              | `{ signatureHex }`                                                             |
| `pqc_verify`     | `message`, `signatureHex`, `publicToken`                       | `{ verified }`                                                                 |
| `pqc_algorithms` | —                                                              | `{ supported, fips }`                                                          |

Behavior:

- `pqc_keygen` generates the pair and a `keyId` (`<algorithm>-<12 hex>`),
  awaits `onSecretKey(keyId, secretKey)`, and only then returns the public
  key. If the callback throws, the tool fails with `KEY_STORAGE_FAILED` and
  the model receives no key.
- `keyId` is checked against `KEY_ID_PATTERN` before `resolveSecretKey` runs,
  so the callback never sees path separators or `..`. A resolver failure maps
  to `KEY_NOT_FOUND` without the application's error message (it stays on the
  error's `cause`).
- `pqc_decrypt` decodes strictly and falls back to base64 — binary plaintext
  is never silently corrupted.
- Errors are thrown as `PqcError[CODE]: message`, so the agent can branch on
  the code.
- Published type declarations reference only `@langchain/core` and
  `@pqc-sdk/core` types (the Zod v3/v4 interop types stay internal).

---

## Usage with a ReAct agent

```typescript
import { createReactAgent } from '@langchain/langgraph/prebuilt';
import type { SecretKey } from '@pqc-sdk/core';
import { createPqcTools } from '@pqc-sdk/langchain';

// Replace with a real secrets manager.
const vault = new Map<string, SecretKey>();

const tools = createPqcTools({
  resolveSecretKey: async (keyId) => {
    const key = vault.get(keyId);
    if (!key) throw new Error(`unknown key ${keyId}`);
    return key;
  },
  onSecretKey: (keyId, secretKey) => {
    vault.set(keyId, secretKey);
  },
});

const agent = createReactAgent({ llm, tools });
```

## Usage in a LangGraph node

```typescript
import { ToolNode } from '@langchain/langgraph/prebuilt';

const toolNode = new ToolNode(createPqcTools({ resolveSecretKey, onSecretKey }));
```

---

## Honest limits

- **Decryption oracle.** `pqc_decrypt` returns plaintext to the model. The
  callbacks keep the _key_ out of the context, not the data it decrypts. Only
  resolve keys whose plaintexts the model is allowed to see.
- **Signing.** `pqc_sign` produces statements under the key owner's identity;
  it is excluded unless `enableSign: true`.
