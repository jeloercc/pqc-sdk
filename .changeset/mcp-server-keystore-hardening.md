---
'@pqc-sdk/mcp-server': minor
---

Stricter keystore checks, a key limit, and no orphaned secret files.

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
