---
'@pqc-sdk/mcp-server': minor
---

Initial release of `@pqc-sdk/mcp-server` (0.1.0).

A ready-to-run [Model Context Protocol](https://modelcontextprotocol.io/) stdio
server that exposes all post-quantum cryptographic operations as native agent
tool calls. Any MCP-compatible host (Claude Desktop, Cursor, Continue, custom
orchestrators) can call PQC operations without any additional wiring.

**Six tools exposed:**

- `pqc_algorithms` — list all supported algorithms and the FIPS-only subset
- `pqc_keygen` — generate a key pair for a given algorithm
- `pqc_encrypt` — encrypt a plaintext string for a public key
- `pqc_decrypt` — decrypt a ciphertext with a secret key
- `pqc_sign` — sign a message with an ML-DSA secret key
- `pqc_verify` — verify a signature against a public key

**Usage (Claude Desktop):**

```json
{
  "mcpServers": {
    "pqc": { "command": "pqc-mcp" }
  }
}
```

All tool handlers are exported as `handleToolForTest()` for unit-testing
without starting the stdio transport.
