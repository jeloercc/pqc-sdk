---
'@pqc-sdk/cli': patch
---

Protect generated secret keys from accidental commits. `init` and `keygen` now
ensure the project `.gitignore` excludes `keys/` and `*.secret.pqc` (creating or
appending idempotently) and report what they added. `init` also no longer
overwrites an existing `example.ts`.
