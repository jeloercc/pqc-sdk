# PQC-SDK — Agent Integration Plan (MPC)

> **Objective:** make `@pqc-sdk/core` a first-class cryptographic primitive
> for any agent framework — LLM tool-calls, MCP servers, LangChain tools,
> A2A protocols, and autonomous multi-agent pipelines.

---

## 1. Verdict

**The SDK is ready to integrate.** It ships a clean, side-effect-free async
API (`pqc.keys.generate`, `pqc.encrypt`, `pqc.decrypt`, `pqc.sign`,
`pqc.verify`, `pqc.encryptStream`, `pqc.collectDecryptStream`) with no
I/O dependencies, zero runtime secrets, and a deterministic serialization
format. Any agent framework that can call an async JavaScript/TypeScript
function can use it today with no wrapper changes.

The three gaps that remain before calling the integration "production-ready":

| Gap                                                                         | Severity | Addressed in |
| --------------------------------------------------------------------------- | -------- | ------------ |
| No structured tool schema (agents can't auto-discover operations)           | High     | Phase 1      |
| No MCP server (model-context-protocol hosts can't load it)                  | High     | Phase 1      |
| No A2A protocol spec (agents can't negotiate secure channels automatically) | Medium   | Phase 2      |

---

## 2. Integration layers (all feasible today)

```
┌─────────────────────────────────────────────────────────────┐
│  LLM / Agent host (Claude, GPT-4o, Gemini, local Ollama)    │
│                                                             │
│  ┌────────────┐  ┌───────────────┐  ┌────────────────────┐  │
│  │ Tool-calls │  │  MCP Server   │  │  LangChain/Graph   │  │
│  │ (JSON API) │  │  (stdio/SSE)  │  │  StructuredTool    │  │
│  └─────┬──────┘  └──────┬────────┘  └────────┬───────────┘  │
│        └────────────────┼──────────────────── ┘             │
│                         ▼                                   │
│              @pqc-sdk/core (this repo)                      │
│   keygen · encrypt · decrypt · sign · verify · stream       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1 — Structured tool exposure (2–3 days)

### 3.1 OpenAI / Anthropic / Gemini tool schema

Create `MPC/agent-tool-spec.json` — a JSON Schema describing every SDK
operation as a tool call. Agents load this at startup and can invoke any
operation without human plumbing.

**Operations to expose:**

| Tool name        | Input                                                            | Output                                    |
| ---------------- | ---------------------------------------------------------------- | ----------------------------------------- |
| `pqc_keygen`     | `{ algorithm: KemAlgorithm \| SignatureAlgorithm }`              | `{ publicToken, secretToken }`            |
| `pqc_encrypt`    | `{ plaintext: string, publicToken: string }`                     | `{ ciphertextHex: string }`               |
| `pqc_decrypt`    | `{ ciphertextHex: string, secretToken: string }`                 | `{ plaintext: string }`                   |
| `pqc_sign`       | `{ message: string, secretToken: string }`                       | `{ signatureHex: string }`                |
| `pqc_verify`     | `{ message: string, signatureHex: string, publicToken: string }` | `{ verified: boolean }`                   |
| `pqc_algorithms` | `{}`                                                             | `{ supported: string[], fips: string[] }` |

Key design rules:

- **All key material travels as `pqcv1.*` token strings** — the SDK's own
  format. Never raw bytes over tool calls (injection risk).
- **secretToken never appears in tool output** — only in input. Agents
  store it in their secure memory / secrets store, not in conversation history.
- Errors map to `PqcErrorCode` strings so agents can branch on them.

### 3.2 MCP server

Create `packages/mcp-server/` — a Node.js MCP server (stdio + SSE transport)
that registers the six tools above. Any MCP-compatible host (Claude Desktop,
Cursor, Bob) can mount it with one config entry.

```json
// .mcp/config.json (example)
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

The server:

- Has **no persistent state** — every call is stateless
- Never logs key material
- Returns `isError: true` with a `PqcErrorCode` on failure
- Supports the `pqc_algorithms` tool so agents can self-discover what's available

### 3.3 LangChain / LangGraph StructuredTool

Create `packages/langchain/` — thin wrappers around each SDK operation using
`@langchain/core`'s `tool()` helper with Zod schemas. Drop-in for any
LangChain agent or graph node.

```typescript
import { pqcEncryptTool, pqcDecryptTool } from '@pqc-sdk/langchain';
const agent = createReactAgent({ tools: [pqcEncryptTool, pqcDecryptTool] });
```

---

## 4. Phase 2 — Agent-to-Agent (A2A) secure channel (1 week)

### 4.1 Problem

Two autonomous agents want to exchange messages that:

1. Only the intended recipient can read (confidentiality)
2. The sender cannot be impersonated (authenticity)
3. Are quantum-resistant (post-quantum security)

### 4.2 Protocol (PQC-A2A v1)

```
Agent A                                    Agent B
  │                                           │
  │── pqc_keygen(ml-kem-768) ──────────────►  │ (B has KEM keypair)
  │── pqc_keygen(ml-dsa-65)  ──────────────►  │ (B has DSA keypair)
  │                                           │
  │◄─── B.kemPublicToken + B.dsaPublicToken ──│ (B publishes identity)
  │                                           │
  │  pqc_sign(B.kemPublicToken, A.dsaSecret)  │ (A verifies B's KEM key)
  │  pqc_encrypt(message, B.kemPublic)       │
  │── ciphertextHex + signatureHex ─────────►│
  │                                           │
  │                         B.pqc_verify()   │
  │                         B.pqc_decrypt()  │
```

**Identity registry:** a simple JSON file (or shared tool memory) mapping
`agentId → { kemPublicToken, dsaPublicToken }`. Can be hosted as an MCP
resource so agents read it automatically.

### 4.3 Multi-agent mesh

For N agents, each agent:

1. Generates one KEM keypair + one DSA keypair at startup
2. Publishes both public tokens to the shared registry
3. Before sending to agent X: encrypts with X's KEM public key, signs with own DSA secret key
4. On receive: verifies sender's DSA signature, then decrypts

This gives **pairwise quantum-resistant encryption** across any mesh of agents
with no trusted third party — just the shared registry.

---

## 5. Phase 3 — Production hardening (ongoing)

| Item                        | Why                                                                       |
| --------------------------- | ------------------------------------------------------------------------- |
| Secret-token TTL / rotation | Agent sessions should rotate KEM keys every N messages                    |
| Key pinning in agent memory | Store `secretToken` in encrypted agent memory, not conversation context   |
| Rate-limit tool calls       | Prevent prompt-injection attacks that force mass key generation           |
| Audit log tool              | `pqc_audit_log` tool that returns which operations were called in session |
| WASM build                  | Enables browser-based agent frameworks (Vercel AI SDK, etc.)              |

---

## 6. Integration compatibility matrix

| Framework                | Mechanism                            | Effort | Status  |
| ------------------------ | ------------------------------------ | ------ | ------- |
| Claude / Bob (Anthropic) | MCP server (stdio)                   | Low    | Phase 1 |
| ChatGPT / GPT-4o         | Tool-call JSON schema                | Low    | Phase 1 |
| LangChain / LangGraph    | StructuredTool (Zod)                 | Low    | Phase 1 |
| AutoGen (Microsoft)      | Python function tool + JS subprocess | Medium | Phase 2 |
| CrewAI                   | Tool class wrapper                   | Medium | Phase 2 |
| Vercel AI SDK            | `tool()` helper                      | Low    | Phase 1 |
| Semantic Kernel          | Native plugin (JS)                   | Medium | Phase 2 |
| Custom A2A mesh          | PQC-A2A v1 protocol                  | Medium | Phase 2 |
| Browser agents           | WASM build                           | High   | Phase 3 |

---

## 7. Recommended merge order for the two open PRs

Before starting Phase 1, merge the branches in this order:

1. **`fix/fips-corrective-pass-2`** first — adds `collectDecryptStream`,
   `FIPS_ALGORITHMS`, and RBG-failure hardening. The MCP server will expose
   `collectDecryptStream` as the safe default for agents.
2. **`feat/ml-kem-512-1024`** second — adds ML-KEM-512 and ML-KEM-1024.
   The tool schema will then advertise all three security levels.

---

## 8. Immediate next actions

```
[ ] Merge fix/fips-corrective-pass-2 → main
[ ] Merge feat/ml-kem-512-1024 → main
[ ] Create packages/mcp-server/ with the 6 tools (Phase 1)
[ ] Create MPC/agent-tool-spec.json (OpenAI/Anthropic schema)
[ ] Create packages/langchain/ with Zod-typed tools (Phase 1)
[ ] Write MPC/a2a-protocol.md with the PQC-A2A v1 spec
[ ] Publish @pqc-sdk/mcp-server to npm
```
