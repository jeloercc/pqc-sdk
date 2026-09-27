---
'@pqc-sdk/langchain': minor
---

Secret keys no longer pass through the model context. **Breaking change** to
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
