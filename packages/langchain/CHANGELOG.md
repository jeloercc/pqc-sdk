# @pqc-sdk/langchain

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
