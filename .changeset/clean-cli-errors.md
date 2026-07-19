---
'@pqc-sdk/cli': patch
---

Expected failures (missing input, refusing to overwrite without `--force`, invalid or mismatched keys) now print a single clean message on stderr and exit with code 1 instead of dumping a stack trace. The input file is validated before the output collision check, and output files are created with the `wx` flag when `--force` is absent, so a file appearing between the check and the write is never clobbered.
