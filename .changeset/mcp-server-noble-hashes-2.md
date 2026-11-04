---
'@pqc-sdk/mcp-server': patch
---

Update `@noble/hashes` from `^1.8.0` to `^2.4.0`, the version `@pqc-sdk/core` already uses, so a single copy is installed. The server only uses `bytesToHex`, `hexToBytes` and `randomBytes` from `@noble/hashes/utils.js`; the test suite passes unchanged.
