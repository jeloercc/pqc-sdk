---
'@pqc-sdk/core': patch
'@pqc-sdk/cli': patch
---

Translate all user-facing text to English: CLI command and flag descriptions,
CLI output (success messages, warnings, audit report, errors), files generated
by `pqc init`, every typed error message in core, the full public API JSDoc
(including examples, which feed the generated API reference), package
descriptions, and both READMEs. Error `code` values are unchanged, so programs
handling `PqcError` by code are unaffected.
