---
'@pqc-sdk/cli': minor
---

Add a `keygen --name` flag and harden `audit`.

- **`keygen --name <name>`**: override the base file name for the generated key
  pair. The default is unchanged (the algorithm, e.g. `ml-kem-768`). The name is
  validated and rejected if it is empty, contains a path separator (`/` or `\`),
  or contains `..`, so keys cannot be written outside the output directory.
- **`audit` is now explicitly heuristic**: a best-effort regex scan that can
  produce false positives and false negatives. The output and docs say so, and
  each run prints a one-line caveat.
- **`audit` bounds the scan**: source files larger than 1 MiB are `stat`ed and
  skipped before reading, and any skipped files are listed in the output.
