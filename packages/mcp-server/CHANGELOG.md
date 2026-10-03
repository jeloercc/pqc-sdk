# @pqc-sdk/mcp-server

## 0.4.1

### Patch Changes

- 1f8b98a: Document the release supply chain in the README: packages are published only from the `release.yml` GitHub Actions workflow, through npm trusted publishing (OIDC) from this version on, and every version carries an npm provenance attestation that `npm audit signatures` verifies.
- Updated dependencies [1f8b98a]
  - @pqc-sdk/core@0.11.2

## 0.4.0

### Minor Changes

- 6ec4ffc: Stricter keystore checks, a key limit, and no orphaned secret files.

  > **0.4.0 may refuse a keystore that 0.3.0 accepted.** On macOS and Linux the
  > server now also refuses a `PQC_KEYSTORE_DIR` that is a symlink, a keystore
  > directory not owned by the server's user, and any parent directory (up to
  > `/`) that is owned by another user or writable by group/others without the
  > sticky bit. A public key file that is a symlink, owned by another user or
  > writable by group/others is now skipped by `pqc_list_keys`. Errors name no
  > paths; the offending path is written to stderr. See "Upgrading from 0.3.x"
  > in the package README.
  - New `PQC_MCP_MAX_KEYS` setting (default `100`): once the keystore holds that
    many secret key files (CLI-imported keys included), `pqc_keygen` fails with
    the new `KEYSTORE_FULL` error. Key generation is serialized so the limit
    holds under concurrent calls. A value that is not a positive integer stops
    the server at startup.
  - Sticky world-writable parents such as `/tmp` (`1777`) remain accepted: other
    users cannot rename entries there, and a keystore directory they pre-create
    is refused because it must be owned by the server's user.
  - If writing a new key's public file fails, its secret file is removed instead
    of being left behind unlisted; `pqc_list_keys` warns on stderr about any
    secret file that has no public file.

### Patch Changes

- Updated dependencies [5e4707a]
  - @pqc-sdk/core@0.11.1

## 0.3.0

### Minor Changes

- dd0d98b: Secret keys no longer pass through the model context. **Breaking change** to
  the tool contract.

  - Secret keys now live in an on-disk keystore: `PQC_KEYSTORE_DIR`, or a
    dedicated per-user default (`~/.local/share/pqc-sdk/agent-keys`). Files use
    the `pqc keygen` format, are written `0600` in a `0700` directory, and are
    read on every call, so keys survive server restarts. Keys created with the
    CLI in that directory are usable without passing through the model.
  - `pqc_keygen` returns `{ keyId, algorithm, publicToken }`; it no longer
    returns the secret key. `pqc_decrypt` and `pqc_sign` take a `keyId` instead
    of a secret token.
  - New `pqc_list_keys` tool.
  - `pqc_sign` is disabled by default and hidden from the tool list; enable it
    with `PQC_MCP_ENABLE_SIGN=1`.
  - `pqc_decrypt` no longer alters plaintext that is not valid UTF-8: it returns
    `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }`.
    `pqc_encrypt` accepts `plaintextBase64` for binary data.
  - Missing or malformed arguments now return `INVALID_ARGUMENT`, a non-hex
    ciphertext returns `INVALID_CIPHERTEXT`, and a non-hex signature verifies as
    `false`, instead of `INTERNAL_ERROR`.

  See the package README for configuration and the migration table from 0.2.x.
  Keys generated with 0.2.x were returned to the model as tool output; consider
  rotating them.

## 0.2.0

### Minor Changes

- 976651a: Initial release of `@pqc-sdk/mcp-server` (0.1.0).

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

### Patch Changes

- Updated dependencies [976651a]
  - @pqc-sdk/core@0.11.0
