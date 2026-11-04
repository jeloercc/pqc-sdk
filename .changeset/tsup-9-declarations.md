---
'@pqc-sdk/core': patch
'@pqc-sdk/langchain': patch
---

Built with tsup 9. The runtime JavaScript is byte-identical to the tsup 8 build. The type declarations now list type-only exports in a separate `export type { … }` clause; the exported names are unchanged.
