---
'@pqc-sdk/cli': minor
---

Write output through the initially opened temporary file and reject overwriting existing key files, including with `keygen --force`.
On POSIX, refuse private output if the filesystem does not apply mode 0600.
