---
'@pqc-sdk/cli': patch
---

Key hygiene on read and on write: `pqc decrypt` (and any command reading a `.secret.pqc` file) now warns — ssh-style, without refusing — when the secret key is group- or other-readable, and recovered plaintext is written with owner-only permissions (0600), including when `--force` overwrites a file that had wider permissions.
