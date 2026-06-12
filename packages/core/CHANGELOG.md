# @pqc-sdk/core

## 0.1.2

### Patch Changes

- 82bbac3: Translate all user-facing text to English: CLI command and flag descriptions,
  CLI output (success messages, warnings, audit report, errors), files generated
  by `pqc init`, every typed error message in core, the full public API JSDoc
  (including examples, which feed the generated API reference), package
  descriptions, and both READMEs. Error `code` values are unchanged, so programs
  handling `PqcError` by code are unaffected.

## 0.1.1

### Patch Changes

- c2dbf93: Fix: el export `version` ahora se inyecta en build time desde el `package.json`
  del paquete, en vez de estar hardcodeado. Los bumps de changesets se reflejan
  solos en ESM, CJS y los types.

## 0.1.0

### Minor Changes

- aac9044: Primera release pública: API de cifrado híbrido ML-KEM-768 + AES-256-GCM,
  firmas ML-DSA-65 con context strings, serialización de keys a base64url, y CLI
  con `init`, `keygen` y `audit`.
