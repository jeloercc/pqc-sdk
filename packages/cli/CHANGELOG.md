# @pqc-sdk/cli

## 0.3.8

### Patch Changes

- Updated dependencies [184516d]
  - @pqc-sdk/core@0.3.8

## 0.3.7

### Patch Changes

- Updated dependencies [b429873]
  - @pqc-sdk/core@0.3.7

## 0.3.6

### Patch Changes

- Updated dependencies [bd18bea]
  - @pqc-sdk/core@0.3.6

## 0.3.5

### Patch Changes

- Updated dependencies [273cefe]
- Updated dependencies [273cefe]
  - @pqc-sdk/core@0.3.5

## 0.3.4

### Patch Changes

- Updated dependencies [914b654]
  - @pqc-sdk/core@0.3.4

## 0.3.3

### Patch Changes

- Updated dependencies [744d59e]
  - @pqc-sdk/core@0.3.3

## 0.3.2

### Patch Changes

- Updated dependencies [04bc7b4]
  - @pqc-sdk/core@0.3.2

## 0.3.1

### Patch Changes

- Updated dependencies [6fcd7a4]
- Updated dependencies [6fcd7a4]
- Updated dependencies [6fcd7a4]
  - @pqc-sdk/core@0.3.1

## 0.3.0

### Patch Changes

- a900943: Protect generated secret keys from accidental commits. `init` and `keygen` now
  ensure the project `.gitignore` excludes `keys/` and `*.secret.pqc` (creating or
  appending idempotently) and report what they added. `init` also no longer
  overwrites an existing `example.ts`.
- Updated dependencies [499b31f]
  - @pqc-sdk/core@0.3.0

## 0.2.0

### Minor Changes

- 1374059: Add a `keygen --name` flag and harden `audit`.

  - **`keygen --name <name>`**: override the base file name for the generated key
    pair. The default is unchanged (the algorithm, e.g. `ml-kem-768`). The name is
    validated and rejected if it is empty, contains a path separator (`/` or `\`),
    or contains `..`, so keys cannot be written outside the output directory.
  - **`audit` is now explicitly heuristic**: a best-effort regex scan that can
    produce false positives and false negatives. The output and docs say so, and
    each run prints a one-line caveat.
  - **`audit` bounds the scan**: source files larger than 1 MiB are `stat`ed and
    skipped before reading, and any skipped files are listed in the output.

### Patch Changes

- Updated dependencies [156cfee]
  - @pqc-sdk/core@0.2.0

## 0.1.2

### Patch Changes

- 82bbac3: Translate all user-facing text to English: CLI command and flag descriptions,
  CLI output (success messages, warnings, audit report, errors), files generated
  by `pqc init`, every typed error message in core, the full public API JSDoc
  (including examples, which feed the generated API reference), package
  descriptions, and both READMEs. Error `code` values are unchanged, so programs
  handling `PqcError` by code are unaffected.
- Updated dependencies [82bbac3]
  - @pqc-sdk/core@0.1.2

## 0.1.1

### Patch Changes

- 8b51922: Fix: la versión que muestra el CLI (`pqc --version` y el header de `--help`)
  ahora se inyecta en build time desde el `package.json` del propio CLI, en vez
  de estar hardcodeada. Los bumps de changesets se reflejan solos.
- Updated dependencies [c2dbf93]
  - @pqc-sdk/core@0.1.1

## 0.1.0

### Minor Changes

- aac9044: Primera release pública: API de cifrado híbrido ML-KEM-768 + AES-256-GCM,
  firmas ML-DSA-65 con context strings, serialización de keys a base64url, y CLI
  con `init`, `keygen` y `audit`.

### Patch Changes

- Updated dependencies [aac9044]
  - @pqc-sdk/core@0.1.0
