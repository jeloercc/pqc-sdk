---
'@pqc-sdk/mcp-server': minor
---

Secret keys no longer pass through the model context. **Breaking change** to
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
