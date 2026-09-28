# MCP Server Design — `@pqc-sdk/mcp-server`

> Model Context Protocol server exposing PQC operations as tools.
> Compatible with Claude Desktop, Cursor, Bob, and any MCP-capable host.

---

## Core rule: secret keys never pass through the model context

The model refers to secret keys only by `keyId`. Secret keys live in a
server-side keystore on disk and are never accepted as a tool argument or
returned in a tool result. Anything in a tool argument or result is part of
the conversation — sent to the model provider, kept in host transcripts and
logs — so key material must not be there at all.

---

## Transport

| Mode    | Use case                                        |
| ------- | ----------------------------------------------- |
| `stdio` | Local agent hosts (Claude Desktop, Bob, Cursor) |

stdout carries the MCP protocol; every log line goes to stderr.

---

## Keystore

Implemented in `packages/mcp-server/src/keystore.ts` (`FileKeyStore`).

| Aspect      | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Location    | `PQC_KEYSTORE_DIR`; if unset, `${XDG_DATA_HOME:-~/.local/share}/pqc-sdk/agent-keys` (`%LOCALAPPDATA%\pqc-sdk\agent-keys` on Windows). Never the CLI's `./keys`.                                                                                                                                                                                                                                                                               |
| Format      | The CLI key-file format (`packages/cli/src/keyfiles.ts`): `<keyId>.public.pqc` + `<keyId>.secret.pqc`, one serialized token per file. No new serialized layout.                                                                                                                                                                                                                                                                               |
| Key ids     | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`. Generated ids are `<algorithm>-<12 hex>`. Files whose name does not match are ignored by `pqc_list_keys`, with one stderr warning.                                                                                                                                                                                                                                                                        |
| Persistence | Every call reads from disk; nothing is cached. Keys survive restarts, and operator changes apply on the next call.                                                                                                                                                                                                                                                                                                                            |
| Writes      | Directory created `0700`, files `0600`. Atomic and non-clobbering: temp file (`wx`, fsync) hard-linked into place, so an existing key is never replaced.                                                                                                                                                                                                                                                                                      |
| Limit       | `PQC_MCP_MAX_KEYS` (default 100) caps the secret key files in the keystore; `pqc_keygen` then fails with `KEYSTORE_FULL`. Generation is serialized in-process; several servers sharing one directory may overshoot slightly. An invalid value stops the server at startup.                                                                                                                                                                    |
| Orphans     | If the public file of a new key fails to write, its secret file is removed; `pqc_list_keys` warns (stderr) about any secret file without a public file.                                                                                                                                                                                                                                                                                       |
| Reads       | POSIX, every call: refuse a symlinked keystore path, a keystore directory not owned by the server user or writable by group/others, and any ancestor (up to `/`) not owned by root or the server user or writable by group/others without the sticky bit. Refuse secret files that are symlinks, foreign-owned or group/other-accessible; skip (with a stderr warning) public files that are symlinks, foreign-owned or group/other-writable. |
| Import      | Operator keys are loaded without the model: `pqc keygen --name <keyId> --out "$PQC_KEYSTORE_DIR"`.                                                                                                                                                                                                                                                                                                                                            |

The model can use **any** key in the directory, so `PQC_KEYSTORE_DIR` must be
a directory dedicated to the agent — never a personal key folder.

---

## Tools

Definitions: `packages/mcp-server/src/tools.ts`. Handlers:
`packages/mcp-server/src/handlers.ts` (`handleTool`).

| Tool             | Input                                                          | Output                                                                         |
| ---------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `pqc_keygen`     | `algorithm?` (default `x-wing`)                                | `{ keyId, algorithm, publicToken }`                                            |
| `pqc_list_keys`  | —                                                              | `{ keys: [{ keyId, algorithm, publicToken }] }`                                |
| `pqc_encrypt`    | `publicToken` + exactly one of `plaintext` / `plaintextBase64` | `{ ciphertextHex }`                                                            |
| `pqc_decrypt`    | `keyId`, `ciphertextHex`                                       | `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }` |
| `pqc_sign`       | `keyId`, `message` — **only with `PQC_MCP_ENABLE_SIGN=1`**     | `{ signatureHex }`                                                             |
| `pqc_verify`     | `message`, `signatureHex`, `publicToken`                       | `{ verified }` (a non-hex signature yields `false`)                            |
| `pqc_algorithms` | —                                                              | `{ supported, fips }`                                                          |

- `pqc_decrypt` decodes strictly (`TextDecoder` with `fatal: true`, BOM kept)
  and falls back to base64, so binary plaintext is never silently corrupted.
- `pqc_sign` is off by default and, when off, is absent from `ListTools`
  (calling it returns `TOOL_DISABLED`). Signing produces statements under the
  operator's identity; enabling it is an explicit operator decision.

---

## Errors

Every failure is an `isError: true` result carrying `{ error, message }`:

| Code                                                              | Source                                                      |
| ----------------------------------------------------------------- | ----------------------------------------------------------- |
| `PqcErrorCode` values (`DECRYPTION_FAILED`, `WRONG_ALGORITHM`, …) | `@pqc-sdk/core`                                             |
| `INVALID_ARGUMENT`                                                | Missing/malformed argument, invalid `keyId` (never echoed)  |
| `INVALID_CIPHERTEXT`                                              | `ciphertextHex` is not hex                                  |
| `KEY_NOT_FOUND`                                                   | No key file for that `keyId`                                |
| `KEYSTORE_INSECURE`                                               | Permission, ownership or symlink check failed               |
| `KEYSTORE_FULL`                                                   | `pqc_keygen` with the keystore at `PQC_MCP_MAX_KEYS`        |
| `INVALID_KEY_FILE`                                                | The secret file does not hold a valid secret key            |
| `TOOL_DISABLED`                                                   | `pqc_sign` called while signing is disabled                 |
| `INTERNAL_ERROR`                                                  | Unexpected failure; detail goes to stderr, not to the model |

Messages carry only key ids, algorithm names and remediation hints — never key
material or filesystem paths.

---

## Honest limits

- **Decryption oracle.** `pqc_decrypt` returns plaintext to the model: whatever
  the model decrypts, it reads. The keystore keeps the _key_ out of the context,
  not the data it decrypts. Grant the server only keys whose plaintexts the
  model is allowed to see.
- **Windows.** POSIX permission and ownership checks are skipped on Windows;
  protect the directory with NTFS ACLs.
- **Key limit, not rate limit.** `PQC_MCP_MAX_KEYS` bounds how many keys can
  accumulate; it does not rate-limit calls. Hosts that need per-session limits
  must enforce them themselves.

---

## Installation in a host (example: Claude Desktop)

```json
{
  "mcpServers": {
    "pqc": {
      "command": "pqc-mcp",
      "env": { "PQC_KEYSTORE_DIR": "/home/me/.local/share/my-agent/pqc-keys" }
    }
  }
}
```
