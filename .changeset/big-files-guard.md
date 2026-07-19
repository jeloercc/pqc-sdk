---
'@pqc-sdk/cli': patch
---

`pqc encrypt` and `pqc decrypt` now refuse inputs above 1 GiB with a clear message instead of an opaque out-of-memory crash or Node's raw 2 GiB `readFile` error — the CLI loads the whole file into memory (streaming is a future core-API project), and the limit is documented in the command help. The redundant full-buffer copy before encryption was also dropped, halving peak memory overhead for large files.
