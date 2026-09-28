---
'@pqc-sdk/langchain': patch
---

README: the usage example now warns that an in-memory `Map` loses every key
when the process restarts, and that anything encrypted to those keys can then
never be decrypted; use durable storage in real deployments.
