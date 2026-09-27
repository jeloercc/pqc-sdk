# @pqc-sdk/mcp-server

MCP (Model Context Protocol) server exposing post-quantum cryptography from
[`@pqc-sdk/core`](https://www.npmjs.com/package/@pqc-sdk/core) as agent tools:
hybrid X-Wing and ML-KEM encryption (FIPS 203), ML-DSA signatures (FIPS 204).
Works with Claude Desktop, Cursor, Continue and any MCP host that speaks stdio.

**Secret keys never pass through the model context.** They live in a keystore
directory on the server's machine; the model refers to them only by `keyId`.

## Install

```bash
npm install -g @pqc-sdk/mcp-server
```

Add it to your host's MCP config (Claude Desktop:
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pqc": {
      "command": "pqc-mcp",
      "env": { "PQC_KEYSTORE_DIR": "/Users/me/.local/share/my-agent/pqc-keys" }
    }
  }
}
```

## The keystore

> [!WARNING]
> **The model can use every key in the keystore directory.** Any secret key
> stored there can be used by the model to decrypt or (if enabled) sign.
> Point `PQC_KEYSTORE_DIR` at a directory **dedicated to this agent** — never
> at your personal key folder or a project's `keys/` directory.

| Setting               | Value                                                                                                                                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PQC_KEYSTORE_DIR`    | Keystore directory. If unset, the server uses its own default: `${XDG_DATA_HOME:-~/.local/share}/pqc-sdk/agent-keys` (`%LOCALAPPDATA%\pqc-sdk\agent-keys` on Windows). It never falls back to the CLI's `./keys`. |
| `PQC_MCP_ENABLE_SIGN` | Set to `1` to expose `pqc_sign`. Off by default.                                                                                                                                                                  |

The server prints its keystore path and signing state to stderr at startup.
stdout is reserved for the MCP protocol.

**Files and permissions.** Each key is a pair of files in the
[`pqc keygen`](https://www.npmjs.com/package/@pqc-sdk/cli) format:
`<keyId>.public.pqc` and `<keyId>.secret.pqc`, one key token per file.

- Keys created by the server: directory `0700`, files `0600`, written
  atomically; an existing key is never overwritten.
- Every call reads from disk, so keys survive restarts and files you add or
  remove take effect on the next call.
- On macOS and Linux the server **refuses** to use a secret key file that is
  readable or writable by group/others, is a symlink, or is owned by another
  user, and refuses a keystore directory writable by group/others. The error
  names the `chmod` that fixes it.
- On Windows these permission checks are skipped; protect the directory with
  NTFS ACLs.

**Bringing your own keys.** Keys never need to pass through the model to be
used — create them with the CLI directly in the keystore:

```bash
npx @pqc-sdk/cli keygen --algorithm x-wing --name billing-inbox --out "$PQC_KEYSTORE_DIR"
```

**Valid key ids.** 1–64 characters: a letter or digit first, then letters,
digits, `_` or `-` (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`). The CLI accepts more
names (for example `alice.work`); files with such names are ignored by the
server, which logs one warning per file to stderr. Rename the pair (e.g. to
`alice-work.public.pqc` / `alice-work.secret.pqc`) to use it.

## Tools

| Tool             | Input                                                          | Output                                                                         |
| ---------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `pqc_keygen`     | `algorithm` (optional, default `x-wing`)                       | `{ keyId, algorithm, publicToken }`                                            |
| `pqc_list_keys`  | —                                                              | `{ keys: [{ keyId, algorithm, publicToken }] }`                                |
| `pqc_encrypt`    | `publicToken` + exactly one of `plaintext` / `plaintextBase64` | `{ ciphertextHex }`                                                            |
| `pqc_decrypt`    | `keyId`, `ciphertextHex`                                       | `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }` |
| `pqc_sign`       | `keyId`, `message` — only with `PQC_MCP_ENABLE_SIGN=1`         | `{ signatureHex }`                                                             |
| `pqc_verify`     | `message`, `signatureHex`, `publicToken`                       | `{ verified }`                                                                 |
| `pqc_algorithms` | —                                                              | `{ supported, fips }`                                                          |

`pqc_decrypt` returns text only when the plaintext is valid UTF-8; anything
else comes back as base64, so binary data is never silently corrupted.
When signing is disabled, `pqc_sign` is not listed at all.

Errors come back as `isError` results with `{ error, message }`. Codes:
the `@pqc-sdk/core` error codes (e.g. `DECRYPTION_FAILED`, `WRONG_ALGORITHM`),
plus `INVALID_ARGUMENT`, `INVALID_CIPHERTEXT`, `KEY_NOT_FOUND`,
`KEYSTORE_INSECURE`, `INVALID_KEY_FILE`, `TOOL_DISABLED` and `INTERNAL_ERROR`.

## What this does not protect

**`pqc_decrypt` is a decryption oracle for the model.** The keystore keeps the
_key_ out of the model context, but whatever the model decrypts, it reads. Only
put keys in the keystore whose plaintexts the model is allowed to see. The
same reasoning is why `pqc_sign` is off by default: a signature is a statement
made under the key owner's identity, and enabling it is your decision.

## Migrating from 0.2.x

0.3.0 changes the tool contract; hosts and prompts written for 0.2.x must be
updated.

| 0.2.x                                         | 0.3.0                                                                                         |
| --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `pqc_keygen` → `{ publicToken, secretToken }` | `pqc_keygen` → `{ keyId, algorithm, publicToken }`; the secret key is written to the keystore |
| `pqc_decrypt { ciphertextHex, secretToken }`  | `pqc_decrypt { keyId, ciphertextHex }`                                                        |
| `pqc_decrypt` → `{ plaintext }`               | `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }`                |
| `pqc_sign { message, secretToken }`           | `pqc_sign { keyId, message }`, only with `PQC_MCP_ENABLE_SIGN=1`                              |
| `pqc_encrypt { plaintext, publicToken }`      | unchanged; `plaintextBase64` is also accepted for binary data                                 |
| —                                             | new `pqc_list_keys`                                                                           |

To keep using a secret token created with 0.2.x, write it to the keystore
yourself — outside the model — as `<keyId>.secret.pqc` (mode `0600`) next to
its `<keyId>.public.pqc`. Because 0.2.x returned secret tokens to the model,
treat keys generated through it as exposed: rotate them if the data they
protect matters.

## License

MIT
