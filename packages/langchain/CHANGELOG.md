# @pqc-sdk/langchain

## 0.3.5

### Patch Changes

- 4feed8a: Narrow the `zod` peer range from `>=3.0.0` to `^3.25.1 || ^4.0.0`. The package imports `zod/v3`, which does not load before zod 3.25.1: zod 3.0–3.24 has no such entry point (`ERR_PACKAGE_PATH_NOT_EXPORTED`), and zod 3.25.0 declares it but ships without the file (`ERR_MODULE_NOT_FOUND`). npm installed the package next to those versions without a warning. The versions the new range excludes never worked, so nothing that worked before stops working.

## 0.3.4

### Patch Changes

- 6e94dbd: Built with tsup 9. The runtime JavaScript is byte-identical to the tsup 8 build. The type declarations now list type-only exports in a separate `export type { … }` clause; the exported names are unchanged.
- Updated dependencies [6e94dbd]
- Updated dependencies [6e94dbd]
  - @pqc-sdk/core@0.11.4

## 0.3.3

### Patch Changes

- Updated dependencies [f3f1d28]
  - @pqc-sdk/core@0.11.3

## 0.3.2

### Patch Changes

- 1f8b98a: Document the release supply chain in the README: packages are published only from the `release.yml` GitHub Actions workflow, through npm trusted publishing (OIDC) from this version on, and every version carries an npm provenance attestation that `npm audit signatures` verifies.
- Updated dependencies [1f8b98a]
  - @pqc-sdk/core@0.11.2

## 0.3.1

### Patch Changes

- 5e4707a: README: the usage example now warns that an in-memory `Map` loses every key
  when the process restarts, and that anything encrypted to those keys can then
  never be decrypted; use durable storage in real deployments.
- Updated dependencies [5e4707a]
  - @pqc-sdk/core@0.11.1

## 0.3.0

### Minor Changes

- dd0d98b: Secret keys no longer pass through the model context. **Breaking change** to
  the exports and tool contract.

  - New `createPqcTools({ resolveSecretKey, onSecretKey?, enableSign? })`
    factory. Tools refer to secret keys by `keyId`; keys move only through the
    application's callbacks. The package performs no I/O.
  - `pqc_keygen` returns `{ keyId, algorithm, publicToken }` and hands the secret
    key to `onSecretKey`. `pqc_decrypt` and `pqc_sign` take a `keyId`.
  - `pqc_sign` is excluded unless `enableSign: true`.
  - Removed exports: `pqcKeygenTool`, `pqcDecryptTool`, `pqcSignTool` and
    `pqcTools`. `pqcEncryptTool`, `pqcVerifyTool` and `pqcAlgorithmsTool` remain.
  - `pqc_decrypt` no longer alters plaintext that is not valid UTF-8: it returns
    `{ encoding: "utf8", plaintext }` or `{ encoding: "base64", plaintextBase64 }`.
    `pqc_encrypt` accepts `plaintextBase64` for binary data.
  - The package now ships TypeScript declarations (`dist/index.d.ts`). 0.2.0
    pointed `types` at a file that was not published, which failed to compile
    under `strict`.

  See the package README for the migration table from 0.2.x. Keys generated with
  0.2.x were returned to the model as tool output; consider rotating them.

## 0.2.0

### Minor Changes

- 976651a: Initial release of `@pqc-sdk/langchain` (0.1.0).

  [LangChain](https://www.langchain.com/) / [LangGraph](https://www.langchain.com/langgraph)
  `StructuredTool` wrappers for all post-quantum cryptographic operations. Drop
  the full suite into any agent in one line, or import tools individually.

  **Six tools, matching the MCP server interface exactly:**

  - `pqcAlgorithmsTool` — list all supported algorithms and the FIPS-only subset
  - `pqcKeygenTool` — generate a key pair for a given algorithm
  - `pqcEncryptTool` — encrypt a plaintext string for a public key
  - `pqcDecryptTool` — decrypt a ciphertext with a secret key
  - `pqcSignTool` — sign a message with an ML-DSA secret key
  - `pqcVerifyTool` — verify a signature against a public key

  Also exports `pqcTools` — an array of all six tools for passing directly to
  `createReactAgent` or any other multi-tool agent constructor.

  **Usage:**

  ```ts
  import { pqcTools } from '@pqc-sdk/langchain';
  import { createReactAgent } from '@langchain/langgraph/prebuilt';

  const agent = createReactAgent({ llm: model, tools: pqcTools });
  ```

  Compatible with `@langchain/core >= 0.3.0` and `zod >= 3.0.0` (peer
  dependencies). Uses the `zod/v3` compatibility subpath internally so it works
  correctly whether the host project uses Zod v3 or v4.

### Patch Changes

- Updated dependencies [976651a]
  - @pqc-sdk/core@0.11.0
