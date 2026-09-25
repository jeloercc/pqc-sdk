# PQC SDK

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcore)](https://www.npmjs.com/package/@pqc-sdk/core)
[![docs](https://img.shields.io/badge/docs-jeloercc.github.io%2Fpqc--sdk-blue)](https://jeloercc.github.io/pqc-sdk/)
[![license](https://img.shields.io/npm/l/%40pqc-sdk%2Fcore)](./LICENSE)

Post-quantum cryptography for JS/TS with safe defaults and zero configuration.
**X-Wing** hybrid KEM (X25519 + ML-KEM-768) + AES-256-GCM by default, pure
**ML-KEM-512/768/1024** (FIPS 203) one option away when FIPS scope or size
dominates, **streaming encryption** for files too large to hold in memory, and
**ML-DSA-44/65/87** (FIPS 204) for signatures — all validated against the
official NIST ACVP test vectors.

Now also available as an **MCP server** (`@pqc-sdk/mcp-server`) and a set of
**LangChain/LangGraph tools** (`@pqc-sdk/langchain`), so AI agents can use
post-quantum cryptography as callable tools with no extra wiring.

**The API surface is designed to take about 30 minutes to adopt** — that is a
claim about this library's ergonomics, not about migrating an organisation to
post-quantum cryptography. The genuinely hard parts of a PQC migration are key
management, format versioning, key rotation, and interoperability with peers
and other languages, and no SDK removes them. What this one tries to do is
keep the cryptographic decisions few and safe, and be explicit about the
format so the rest is tractable: see
[why PQC now](https://jeloercc.github.io/pqc-sdk/guide/why-pqc) for the threat
that motivates the work, and
[the serialization format](./docs/serialization-format.md) for the byte layout
you would need to interoperate with.

> **Security status, up front.** This SDK has **not** had an independent
> third-party cryptographic audit, and does not claim one; the reviews in
> `docs/` are internal and AI-assisted. As with any JavaScript implementation
> there are **no constant-time guarantees**, and there is **no memory
> zeroization** of secrets, plaintext or key material — JS offers no reliable
> primitive for it. `@noble/post-quantum` has no independent audit either
> (self-audit 04/2026). Read the full threat model in
> [SECURITY.md](./SECURITY.md) before adopting this for anything that matters,
> and [How this is verified](#how-this-is-verified) for what _is_ checked and
> how.

> **Breaking in 0.8.0:** `pqc.keys.generate()` with no arguments now returns
> an **X-Wing** hybrid pair (X25519 + ML-KEM-768), not pure ML-KEM-768 — a
> break in either half still leaves the other standing, which is the same
> reasoning behind TLS's `X25519MLKEM768`, Signal's PQXDH, and the BSI and
> ANSSI recommendations. **JavaScript consumers get no compile-time signal**,
> so read
> [migrating to 0.8.0](https://github.com/jeloercc/pqc-sdk/blob/main/docs/MIGRATION-0.8.md)
> before upgrading. Pure ML-KEM-768 stays first-class and one line away —
> `pqc.keys.generate({ algorithm: 'ml-kem-768' })` — and is the right choice
> when FIPS certification scope or size/speed dominate.

---

## Quickstart

```bash
npm install @pqc-sdk/core
```

```ts
import { pqc } from '@pqc-sdk/core';

// Hybrid encryption (X-Wing, the default)
const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('secret', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

// Signatures (ML-DSA-65)
const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('document', signer.secretKey);
const valid = await pqc.verify('document', signature, signer.publicKey);

// Pure FIPS 203 (ML-KEM-768), when FIPS scope dominates
const fipsPair = await pqc.keys.generate({ algorithm: 'ml-kem-768' });
```

Or bootstrap a whole project with the CLI:

```bash
npx @pqc-sdk/cli init
```

**Full documentation at [jeloercc.github.io/pqc-sdk](https://jeloercc.github.io/pqc-sdk/)**:
[5-minute quickstart](https://jeloercc.github.io/pqc-sdk/guide/quickstart),
[hybrid encryption explained](https://jeloercc.github.io/pqc-sdk/guide/hybrid-encryption),
[streaming large files](https://jeloercc.github.io/pqc-sdk/guide/streaming-encryption),
[runtime compatibility](https://jeloercc.github.io/pqc-sdk/compatibility) and
[API reference](https://jeloercc.github.io/pqc-sdk/api/).

---

## Packages

| Package                                                        | What it does                                                                                                                                            | Tests |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| [`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) | The SDK: hybrid encryption, signatures, key handling, streaming. Node 20+, Deno, Workers, RN.                                                           | 416   |
| [`@pqc-sdk/cli`](https://www.npmjs.com/package/@pqc-sdk/cli)   | `pqc init` / `keygen` / `encrypt` / `decrypt` / `audit` — scaffolding, keys, file encryption, and a heuristic scan for legacy crypto.                   | 54    |
| [`@pqc-sdk/mcp-server`](./packages/mcp-server/)                | MCP stdio server exposing all 6 PQC operations as agent tools (`pqc_algorithms`, `pqc_keygen`, `pqc_encrypt`, `pqc_decrypt`, `pqc_sign`, `pqc_verify`). | 13    |
| [`@pqc-sdk/langchain`](./packages/langchain/)                  | LangChain / LangGraph `StructuredTool` wrappers for the same 6 operations, plus a `pqcTools` bundle array.                                              | 14    |

**497 tests across all four packages, all passing.**

---

## Agent integration (MCP + LangChain)

### MCP server

The `@pqc-sdk/mcp-server` package is a ready-to-run
[Model Context Protocol](https://modelcontextprotocol.io/) stdio server. Any
MCP-compatible host (Claude Desktop, Cursor, Continue, custom orchestrators)
can call PQC operations directly as tool calls.

```bash
npm install -g @pqc-sdk/mcp-server

# Run the server (stdin/stdout MCP transport)
pqc-mcp
```

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pqc": {
      "command": "pqc-mcp"
    }
  }
}
```

The six tools exposed:

| Tool             | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `pqc_algorithms` | List all supported algorithms and the FIPS-only subset |
| `pqc_keygen`     | Generate a key pair for a given algorithm              |
| `pqc_encrypt`    | Encrypt a plaintext string for a public key            |
| `pqc_decrypt`    | Decrypt a ciphertext with a secret key                 |
| `pqc_sign`       | Sign a message with an ML-DSA secret key               |
| `pqc_verify`     | Verify a signature against a public key                |

### LangChain / LangGraph tools

```bash
npm install @pqc-sdk/langchain @pqc-sdk/core
```

```ts
import { pqcTools } from '@pqc-sdk/langchain';
import { createReactAgent } from '@langchain/langgraph/prebuilt';

// Drop the full suite into any LangChain/LangGraph agent
const agent = createReactAgent({ tools: pqcTools, llm: model });
```

Each tool is also available individually (`pqcKeygenTool`,
`pqcEncryptTool`, `pqcDecryptTool`, `pqcSignTool`, `pqcVerifyTool`,
`pqcAlgorithmsTool`).

Full design specification, A2A secure-channel protocol and OpenAI/Anthropic
tool schema: [`MPC/`](./MPC/).

---

## How this is verified

Read this first if you are evaluating whether to trust this SDK.

- **Official NIST ACVP vectors run in CI** on every commit — ML-KEM-512/768/1024
  (FIPS 203) and ML-DSA-44/65/87 (FIPS 204), plus the X-Wing draft's Appendix C
  vectors. Not a sample: the published vector sets.
- **Five runtimes validated by actual execution, never by inference** — Node,
  Deno, Cloudflare Workers, the Hermes engine, and a **physical Android
  device**. A runtime gets ✅ only after the real roundtrip ran there; anything
  else stays ⏳ and says what is missing.
- **The parser is fuzzed** against arbitrary and hand-picked hostile input,
  asserting it always fails closed rather than returning an attacker-shaped key.
- **Property-based tests** (`fast-check`) assert the invariants over arbitrary
  payloads, including that any single-byte tamper fails closed.
- **Golden wire-format vectors** lock every envelope version, and regenerating
  them requires an acknowledged breaking change — the suite failing is the
  intended tripwire.
- **A mutation matrix** tampers every region of a streaming envelope
  independently — truncation, reorder, duplication, cross-stream splice,
  final-flag games — each asserting the documented error code. The streaming
  envelope binds every chunk to its index and marks the final chunk, adopting
  [age](https://github.com/C2SP/C2SP/blob/main/age.md)'s STREAM construction
  verbatim.

We never implement cryptographic primitives: ML-KEM/ML-DSA come from
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and
AES-GCM from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
That means the interesting risk is **not** in the primitives — it is in the
layers this SDK does own: the envelope format, key serialization, nonce
derivation, and fail-closed behaviour on malformed input.

| Layer                         | How it is verified                                                                                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Primitive correctness         | Official **NIST ACVP vectors** for ML-KEM-512/768/1024 and ML-DSA-44/65/87, plus X-Wing Appendix C vectors — [`nist-vectors.test.ts`](./packages/core/src/nist-vectors.test.ts), [`xwing-vectors.test.ts`](./packages/core/src/xwing-vectors.test.ts)             |
| Wire format stability         | **Golden serialization vectors** for every envelope version (v1, v2, streaming), regenerated only behind an acknowledged breaking change — [`src/vectors/`](./packages/core/src/vectors/), [`golden-vectors.test.ts`](./packages/core/src/golden-vectors.test.ts) |
| Parser hostility              | **Fuzzing** of `keys.deserialize` against arbitrary and hand-picked hostile input, asserting it always fails closed — [`deserialize-fuzz.test.ts`](./packages/core/src/deserialize-fuzz.test.ts)                                                                  |
| Roundtrip + tamper invariants | **Property-based tests** (`fast-check`): decrypt(encrypt(x)) === x for arbitrary payloads, and any single-byte tamper fails closed — [`properties.test.ts`](./packages/core/src/properties.test.ts)                                                               |
| Streaming envelope            | **Mutation matrix** tampering every region independently — truncation, reorder, duplication, cross-stream splice, final-flag games — each asserting the documented `PqcError` code — [`stream-mutations.test.ts`](./packages/core/src/stream-mutations.test.ts)   |
| Format specification          | The normative byte layout, so the tests above check an intent rather than the current output — [`docs/serialization-format.md`](./docs/serialization-format.md)                                                                                                   |
| Review                        | Pre-launch findings report ([`docs/AUDIT-2026-06.md`](./docs/AUDIT-2026-06.md)) and source-level security review ([`docs/SECURITY-REVIEW-2026-06.md`](./docs/SECURITY-REVIEW-2026-06.md))                                                                         |
| Runtime claims                | Node, Deno, Cloudflare Workers, Hermes and a physical React Native device — each ✅ only after the roundtrip actually ran there — [`docs/compatibility.md`](./docs/compatibility.md)                                                                              |

Coverage floor is 90%; the suite currently runs **497 tests** across all
packages. Run it yourself with `pnpm turbo run lint test build --force`.

**What these reviews are not.** `docs/AUDIT-2026-06.md` and
`docs/SECURITY-REVIEW-2026-06.md` are internal, AI-assisted reviews. They are
**not** an independent third-party cryptographic audit, and the SDK does not
claim to be audited. `@noble/post-quantum` itself has no independent audit yet
either (self-audit 04/2026).

**Known limitation worth reading before you adopt this: there is no memory
zeroization.** Shared secrets, decrypted plaintext and secret-key bytes are
not wiped after use — JavaScript offers no reliable primitive for it and
`@noble` does not zeroize either, so it is an ecosystem limitation this SDK
cannot fully close. The full threat model, including the absence of
constant-time guarantees, is in [SECURITY.md](./SECURITY.md).

To report a vulnerability, see [SECURITY.md](./SECURITY.md) — please do not
open public issues.

---

## FIPS 203/204/205 conformance self-assessment

This is the thing that distinguishes this SDK from wrapping
`@noble/post-quantum` directly: `docs/compliance/` carries a clause-by-clause
self-assessment against all three PQC standards this SDK touches. Each matrix
quotes the normative text verbatim, states whether the requirement applies to
this codebase, and assigns one of a closed set of statuses — `CONFORMING`,
`CONFORMING (delegated)`, `NONCONFORMING`, `INDETERMINATE`, `NOT APPLICABLE`
and so on — never a bare pass/fail. A row moves to `CONFORMING` only on the
strength of a named, executed test; every row cites a file, a line, or a test
name as its evidence, never a narrative claim alone.

- [`FIPS-203-MATRIX.md`](./docs/compliance/FIPS-203-MATRIX.md) — 21
  requirements, ML-KEM-512/768/1024
- [`FIPS-204-MATRIX.md`](./docs/compliance/FIPS-204-MATRIX.md) — 22
  requirements, ML-DSA-44/65/87
- [`FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md) — 21
  requirements registered, all `NOT APPLICABLE` — SLH-DSA is not
  implemented; see [below](#slh-dsa-fips-205-not-implemented-by-scope-decision)

### What was found, and fixed

Across FIPS 203 and FIPS 204, six findings were opened as `NONCONFORMING` and
closed by an actual code change, each with an executed regression test cited in
the matrix:

- **F203-19 — Floating-point arithmetic in `Compress_d`** (ML-KEM). FIPS 203
  prohibits floating-point arithmetic; JavaScript's `/` is always IEEE-754
  double division. Replaced with integer-only bit-shift arithmetic, verified
  bit-exact against the original over all 36,619 `(q, d)` pairs.
- **F204-13 — Floating-point arithmetic in `Decompose`/`Power2Round`/`HINT_M`**
  (ML-DSA). Same class of violation. Replaced with integer-only BigInt/bit-shift
  arithmetic, verified bit-exact over all of Z_q (8,380,417 values) for both
  branches.
- **F203-18 — Branch-based implicit-reject selection** in ML-KEM decapsulation.
  Which of two candidate shared secrets survived was decided by a ternary on the
  secret reject flag. Replaced with a byte-wise arithmetic mask so every output
  byte is computed from both candidates unconditionally and the branch
  disappears.
- **F204-10 — Missing zeroization on the ML-DSA verification path.** Upstream's
  `internal.verify` had zero `cleanBytes` calls; every decoded or recomputed
  intermediate survived the call. Wrapped in `try`/`finally` so all nine
  intermediates are wiped on every exit, including early rejections, while
  leaving caller-owned buffers untouched.
- **F203-11 — RBG failure misattributed as an invalid key.** An entropy failure
  during ML-KEM encapsulation was caught by the same handler as a malformed
  public key, surfacing as `INVALID_KEY` instead of `RBG_FAILURE`. Given a
  dedicated error code, checked before the generic handler.
- **F204-08 — Wrong-length public key throwing instead of returning `false`.**
  FIPS 204 §3.6.2 requires `ML-DSA.Verify` to _return_ `false` on a
  wrong-length key, not throw. The SDK's own length check ran outside the `try`
  block that would have normalized it; moved inside.

Three of these (F203-11, F203-18, F203-19) were first closed for the
standalone `ml-kem-768` algorithm, then found still open on the default
`x-wing` path — a different scope, caught and fixed separately.

**What is not claimed:** This is self-assessment, not CMVP validation.
Nothing here has been submitted to NIST's CAVP or CMVP. ACVP known-answer
vectors passing is assurance evidence, not proof of every clause — the
floating-point findings above are the standing counterexample: those vectors
passed for the entire time the requirement was breached, because a KAT cannot
see _how_ a bit-identical result was computed.

---

## SLH-DSA (FIPS 205): not implemented, by scope decision

**ML-DSA-65 is the recommended signature algorithm in this SDK.** SLH-DSA
(FIPS 205) is not implemented here — a deliberate scope decision recorded with
dates and reasoning in
[`docs/compliance/FIPS-205-MATRIX.md`](./docs/compliance/FIPS-205-MATRIX.md).

- **Signature size.** Per FIPS 205 Table 2, SLH-DSA signatures range from
  7,856 bytes (SLH-DSA-128s) to 49,856 bytes (SLH-DSA-256f) — roughly 2.4×
  to 15× larger than ML-DSA-65's 3,309-byte signature.
- **Performance.** SLH-DSA/SPHINCS+ makes tens of thousands of hash invocations
  per operation (WOTS+ chains, a FORS forest, a hypertree of Merkle trees). No
  native acceleration.
- **Use-case fit.** SLH-DSA targets firmware signing and long-lived roots of
  trust, not request/response or file-level operations. If you have a genuine
  SLH-DSA requirement — a long-lived root or a regulatory mandate naming it —
  you likely need a CMVP-validated cryptographic module, not this library.

This decision is reopenable: open an issue if you have a concrete use case.

---

## Monorepo structure

```
packages/core         @pqc-sdk/core          — the SDK (TypeScript, ESM + CJS)
packages/cli          @pqc-sdk/cli           — CLI built on top of core
packages/mcp-server   @pqc-sdk/mcp-server    — MCP stdio server for AI agents
packages/langchain    @pqc-sdk/langchain     — LangChain/LangGraph tool wrappers
apps/docs             @pqc-sdk/docs          — documentation site (VitePress + typedoc)
examples/             example projects: node, deno, cloudflare-workers, hermes-standalone
docs/                 serialization format, compliance matrices, audit reports
MPC/                  agent integration specs: MCP, LangChain, A2A protocol, tool schemas
```

Turborepo + pnpm workspaces. Build order: `core` → `cli` / `mcp-server` /
`langchain` (parallel) → `docs`.

See [CONTRIBUTING.md](./CONTRIBUTING.md) to run the repo locally.

---

## License

[MIT](./LICENSE)
