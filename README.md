# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

> Post-quantum cryptography for JS/TS — hybrid encryption, digital signatures,
> streaming, and now **native AI-agent tool support** via MCP and LangChain.
> 497 tests. FIPS 203/204 self-assessed. Safe defaults. Zero configuration.

---

## What is post-quantum cryptography, and why now?

Classical public-key cryptography (RSA, ECDH, ECDSA) is broken in polynomial
time by a sufficiently large quantum computer running Shor's algorithm. One
does not exist yet — but **harvest-now, decrypt-later** attacks are already
occurring: adversaries store encrypted traffic today to decrypt it once a
capable quantum computer exists. For any data that needs to stay secret for
more than a few years, the migration window is now, not when the threat
materialises.

NIST finalised three post-quantum standards in 2024:

| Standard     | Algorithm family                  | What it replaces          |
| ------------ | --------------------------------- | ------------------------- |
| **FIPS 203** | ML-KEM (lattice-based KEM)        | RSA / ECDH key exchange   |
| **FIPS 204** | ML-DSA (lattice-based signatures) | ECDSA / RSA signatures    |
| **FIPS 205** | SLH-DSA (hash-based signatures)   | Long-lived roots of trust |

This SDK implements FIPS 203 and FIPS 204 in pure TypeScript, with a
clause-by-clause self-assessment against both standards, 6 closed
`NONCONFORMING` findings, and validated NIST ACVP vectors for every parameter
set. **SLH-DSA (FIPS 205) is deliberately not implemented** — see
[SLH-DSA scope decision](#slh-dsa-fips-205-not-implemented-by-scope-decision).

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AI Agent Layer                              │
│                                                                     │
│  ┌──────────────────────┐       ┌──────────────────────────────┐   │
│  │  @pqc-sdk/mcp-server │       │     @pqc-sdk/langchain       │   │
│  │  (MCP stdio server)  │       │  (LangChain StructuredTools) │   │
│  │                      │       │                              │   │
│  │  Claude Desktop      │       │  LangGraph agents            │   │
│  │  Cursor / Continue   │       │  OpenAI tool-calling         │   │
│  │  Custom MCP hosts    │       │  Anthropic tool-use          │   │
│  └──────────┬───────────┘       └─────────────┬────────────────┘   │
└─────────────│─────────────────────────────────│────────────────────┘
              │                                 │
              └──────────────┬──────────────────┘
                             │  calls
┌────────────────────────────▼────────────────────────────────────────┐
│                       @pqc-sdk/core                                 │
│                                                                     │
│  pqc.keys.generate()    pqc.encrypt()    pqc.sign()                │
│  pqc.keys.serialize()   pqc.decrypt()    pqc.verify()              │
│  encryptStream()        collectDecryptStream()                      │
│                                                                     │
│  ┌────────────────────┐  ┌───────────────────┐                     │
│  │  ML-KEM-512/768/   │  │  ML-DSA-44/65/87  │                     │
│  │  1024  (FIPS 203)  │  │  (FIPS 204)       │                     │
│  │  + X-Wing hybrid   │  │                   │                     │
│  └────────────────────┘  └───────────────────┘                     │
│                                                                     │
│  Primitives: @noble/post-quantum + @noble/ciphers (never ours)     │
└────────────────────────────────────────────────────────────────────┘
              │
┌─────────────▼─────────────────┐
│        @pqc-sdk/cli           │
│  pqc init / keygen /          │
│  encrypt / decrypt / audit    │
└───────────────────────────────┘
```

---

## AI agent integration — start here if you use LLMs

This SDK ships first-class support for AI agents. Both integrations expose the
same six operations: list algorithms, generate keys, encrypt, decrypt, sign,
verify.

### Option A — MCP server (Claude, Cursor, Continue, any MCP host)

The [Model Context Protocol](https://modelcontextprotocol.io/) lets any
compatible AI host call PQC operations as native tool calls — no custom wiring,
no API server, just a local stdio process.

```bash
npm install -g @pqc-sdk/mcp-server
```

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pqc": {
      "command": "pqc-mcp"
    }
  }
}
```

**Cursor / Continue** — add the same block to your editor's MCP config.

Once connected, the model can call:

```
Tool call: pqc_algorithms
→ { "supported": ["x-wing","ml-kem-768",...], "fips": ["ml-kem-768",...] }

Tool call: pqc_keygen { "algorithm": "x-wing" }
→ { "algorithm": "x-wing", "publicToken": "pqc1pub...", "secretToken": "pqc1sec..." }

Tool call: pqc_encrypt { "plaintext": "hello", "publicToken": "pqc1pub..." }
→ { "ciphertextHex": "03f7a2..." }

Tool call: pqc_decrypt { "ciphertextHex": "03f7a2...", "secretToken": "pqc1sec..." }
→ { "plaintext": "hello" }

Tool call: pqc_sign { "message": "doc", "secretToken": "pqc1sec..." }
→ { "signatureHex": "b9e1..." }

Tool call: pqc_verify { "message": "doc", "signatureHex": "b9e1...", "publicToken": "pqc1pub..." }
→ { "verified": true }
```

**Tool inventory:**

| Tool             | Input                                    | Output                         |
| ---------------- | ---------------------------------------- | ------------------------------ |
| `pqc_algorithms` | _(none)_                                 | `{ supported[], fips[] }`      |
| `pqc_keygen`     | `algorithm` (optional, default `x-wing`) | `{ publicToken, secretToken }` |
| `pqc_encrypt`    | `plaintext`, `publicToken`               | `{ ciphertextHex }`            |
| `pqc_decrypt`    | `ciphertextHex`, `secretToken`           | `{ plaintext }`                |
| `pqc_sign`       | `message`, `secretToken`                 | `{ signatureHex }`             |
| `pqc_verify`     | `message`, `signatureHex`, `publicToken` | `{ verified }`                 |

### Option B — LangChain / LangGraph tools

```bash
npm install @pqc-sdk/langchain @pqc-sdk/core
```

```ts
import { pqcTools } from '@pqc-sdk/langchain';
import { createReactAgent } from '@langchain/langgraph/prebuilt';

// Drop the entire PQC suite into any agent
const agent = createReactAgent({ llm: model, tools: pqcTools });

// Or pick individual tools
import {
  pqcAlgorithmsTool,
  pqcKeygenTool,
  pqcEncryptTool,
  pqcDecryptTool,
  pqcSignTool,
  pqcVerifyTool,
} from '@pqc-sdk/langchain';
```

Each tool is a standard LangChain `StructuredTool` with a Zod input schema,
a description, and a name that matches the MCP server above — the same six
operations work identically in both integration paths.

### Agent-to-Agent secure channel (A2A)

The [`MPC/a2a-protocol.md`](./MPC/a2a-protocol.md) specification describes a
protocol for two AI agents to establish a post-quantum-secured communication
channel using ML-KEM (key encapsulation) and ML-DSA (identity attestation).
The full set of design documents is in [`MPC/`](./MPC/).

---

## SDK quickstart (humans)

```bash
npm install @pqc-sdk/core
```

```ts
import { pqc } from '@pqc-sdk/core';

// ── Hybrid encryption (X-Wing default) ────────────────────────────────────
const pair = await pqc.keys.generate(); // X-Wing by default
const ciphertext = await pqc.encrypt('secret', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

// ── Digital signatures (ML-DSA-65) ────────────────────────────────────────
const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('document', signer.secretKey);
const valid = await pqc.verify('document', signature, signer.publicKey);

// ── Pure FIPS 203 (ML-KEM-768), when FIPS scope dominates ─────────────────
const fipsPair = await pqc.keys.generate({ algorithm: 'ml-kem-768' });

// ── Streaming encryption (large files) ────────────────────────────────────
import { encryptStream, collectDecryptStream } from '@pqc-sdk/core/stream';
const encrypted = encryptStream(readableStream, pair.publicKey);
const decrypted = await collectDecryptStream(encrypted, pair.secretKey);
```

Or bootstrap a whole project with the CLI:

```bash
npx @pqc-sdk/cli init
# Creates config, dev keys, .gitignore, and example.ts in ~5 seconds
```

**Full documentation → [jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**

---

## Packages

| Package                                                        | What it does                                                                             | Tests |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | The SDK — encryption, signatures, key handling, streaming. Node 20+, Deno, Workers, RN.  | 416   |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init / keygen / encrypt / decrypt / audit` — dev scaffolding and file-level crypto. | 54    |
| [`@pqc-sdk/mcp-server`](./packages/mcp-server/)                | MCP stdio server — 6 PQC tools callable by any MCP-compatible AI host.                   | 13    |
| [`@pqc-sdk/langchain`](./packages/langchain/)                  | LangChain / LangGraph `StructuredTool` wrappers + `pqcTools` bundle.                     | 14    |

**497 tests · all passing · 90 %+ coverage on core**

---

## Supported algorithms

```
Encryption / Key Exchange
─────────────────────────────────────────────────────────────────
  x-wing          X25519 + ML-KEM-768 + AES-256-GCM   ← default
  ml-kem-512      FIPS 203 §4 (security category 1)
  ml-kem-768      FIPS 203 §4 (security category 3)   ← FIPS-only
  ml-kem-1024     FIPS 203 §4 (security category 5)

Signatures
─────────────────────────────────────────────────────────────────
  ml-dsa-44       FIPS 204 §5 (security category 2)
  ml-dsa-65       FIPS 204 §5 (security category 3)   ← recommended
  ml-dsa-87       FIPS 204 §5 (security category 5)
```

**Why X-Wing by default?** A break in either the classical (X25519) or
post-quantum (ML-KEM-768) component still leaves the other standing — the same
reasoning behind TLS `X25519MLKEM768`, Signal's PQXDH, and the BSI/ANSSI
hybrid recommendations. Use `ml-kem-768` when FIPS certification scope or
binary size dominate.

---

## How this is verified

> Read this before evaluating whether to trust this SDK.

We never implement cryptographic primitives: ML-KEM/ML-DSA come from
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
AES-GCM from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
The risk we carry is the layer _around_ them: envelope format, key
serialization, nonce derivation, fail-closed parsing.

| Layer                 | How it is verified                                                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Primitive correctness | **NIST ACVP vectors** for ML-KEM-512/768/1024 and ML-DSA-44/65/87, plus X-Wing Appendix C — [`nist-vectors.test.ts`](./packages/core/src/nist-vectors.test.ts)                                       |
| Wire format stability | **Golden vectors** for every envelope version (v1, v2, streaming) — regenerated only behind an acknowledged breaking change — [`golden-vectors.test.ts`](./packages/core/src/golden-vectors.test.ts) |
| Parser hostility      | **Fuzzing** of `keys.deserialize` against arbitrary and hostile input — always fails closed — [`deserialize-fuzz.test.ts`](./packages/core/src/deserialize-fuzz.test.ts)                             |
| Roundtrip + tamper    | **Property-based tests** (`fast-check`): decrypt(encrypt(x)) === x, any single-byte tamper fails closed — [`properties.test.ts`](./packages/core/src/properties.test.ts)                             |
| Streaming envelope    | **Mutation matrix** tampering every region independently — truncation, reorder, duplication, cross-stream splice — [`stream-mutations.test.ts`](./packages/core/src/stream-mutations.test.ts)        |
| Format specification  | Normative byte layout — [`docs/serialization-format.md`](./docs/serialization-format.md)                                                                                                             |
| Security review       | Pre-launch findings + source-level review — [`docs/AUDIT-2026-06.md`](./docs/AUDIT-2026-06.md)                                                                                                       |
| Runtime claims        | Node, Deno, Workers, Hermes, physical Android device — ✅ only after the real roundtrip ran — [`docs/compatibility.md`](./docs/compatibility.md)                                                     |
| Interop               | CIRCL (Go) cross-check for ML-DSA and X-Wing shared secrets — [`interop-circl.test.ts`](./packages/core/src/interop-circl.test.ts)                                                                   |

**What these reviews are not.** The audit docs are internal, AI-assisted
reviews — **not** an independent third-party cryptographic audit. There are
no constant-time guarantees in JavaScript, and no memory zeroization of
secrets (no reliable JS primitive exists). Full threat model:
[SECURITY.md](./SECURITY.md).

---

## FIPS 203/204/205 conformance self-assessment

`docs/compliance/` carries a clause-by-clause self-assessment against all
three PQC standards. Each matrix quotes normative text verbatim, assigns a
status from a closed vocabulary (`CONFORMING`, `NONCONFORMING`, `INDETERMINATE`,
`NOT APPLICABLE`), and cites a named, executed test as evidence — never a
narrative claim alone.

- [`FIPS-203-MATRIX.md`](./docs/compliance/FIPS-203-MATRIX.md) — 21 requirements, ML-KEM-512/768/1024
- [`FIPS-204-MATRIX.md`](./docs/compliance/FIPS-204-MATRIX.md) — 22 requirements, ML-DSA-44/65/87
- [`FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md) — 21 requirements, all `NOT APPLICABLE` (SLH-DSA not implemented)

### Six NONCONFORMING findings closed

| ID          | Finding                                                                         | Fix                                                                                 |
| ----------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **F203-19** | Floating-point in `Compress_d` — JS `/` is IEEE-754 double; FIPS 203 forbids it | Integer-only bit-shift arithmetic, verified bit-exact over all 36,619 `(q,d)` pairs |
| **F204-13** | Floating-point in `Decompose` / `Power2Round` / `HINT_M`                        | Integer-only BigInt/bit-shift, verified over all 8,380,417 values of Z_q            |
| **F203-18** | Branch-based implicit-reject — secret flag visible in control flow              | Byte-wise arithmetic mask; both candidate secrets computed unconditionally          |
| **F204-10** | Missing zeroization on ML-DSA verify path — 9 intermediates leaked              | `try`/`finally` with `cleanBytes` on every exit path                                |
| **F203-11** | RBG failure misattributed as `INVALID_KEY`                                      | Dedicated `RBG_FAILURE` error code, checked before the generic handler              |
| **F204-08** | Wrong-length public key throws instead of returning `false`                     | Length check moved inside the `try` block                                           |

Three of these (F203-11/18/19) were first closed for `ml-kem-768`, then found
still open on the `x-wing` path — different scope, caught and fixed separately.

**Not claimed:** This is self-assessment, not CMVP validation. ACVP vectors
passing is assurance evidence, not proof of every clause — the floating-point
findings above passed KATs the entire time the requirement was breached.

---

## SLH-DSA (FIPS 205): not implemented, by scope decision

ML-DSA-65 is the recommended signature algorithm. SLH-DSA (FIPS 205) is
deliberately excluded — see
[`FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md) for the full
rationale. Short version:

- **Size:** SLH-DSA signatures are 7,856–49,856 bytes vs ML-DSA-65's 3,309 bytes
- **Speed:** tens of thousands of hash invocations per operation in pure JS
- **Fit:** targets firmware signing / long-lived roots, not request/response flows

If you need SLH-DSA for a regulatory mandate, you likely need a
CMVP-validated module. Open an issue if you have a concrete use case.

---

## Monorepo structure

```
packages/
  core/          @pqc-sdk/core        — crypto SDK  (ESM + CJS, TypeScript)
  cli/           @pqc-sdk/cli         — CLI tool
  mcp-server/    @pqc-sdk/mcp-server  — MCP stdio server for AI agents
  langchain/     @pqc-sdk/langchain   — LangChain/LangGraph tool wrappers
apps/
  docs/          @pqc-sdk/docs        — VitePress documentation site
examples/        node · deno · cloudflare-workers · hermes-standalone
docs/            serialization format · compliance matrices · audit reports
MPC/             agent integration specs (MCP, LangChain, A2A, tool schemas)
```

Build order (Turborepo): `core` → `cli` / `mcp-server` / `langchain` (parallel) → `docs`

See [CONTRIBUTING.md](./CONTRIBUTING.md) to run the repo locally.

> **Breaking in 0.8.0:** `pqc.keys.generate()` with no arguments now returns
> an **X-Wing** hybrid pair, not pure ML-KEM-768. Read
> [migrating to 0.8.0](https://github.com/jeloercc/pqc-sdk/blob/main/docs/MIGRATION-0.8.md)
> before upgrading if you depend on the old default.

---

## License

[MIT](./LICENSE)
