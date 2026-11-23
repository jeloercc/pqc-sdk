---
'@pqc-sdk/core': patch
---

Clear owned ML-KEM sampling, polynomial and encoding scratch on normal and
exceptional exits. Preserve caller-owned inputs, returned secrets, prepared-cache
reuse and existing cryptographic outputs. Add pinned official public sample
comparisons and cleanup/failure regressions; clarify their assurance limits.
