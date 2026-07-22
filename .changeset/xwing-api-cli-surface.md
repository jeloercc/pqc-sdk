---
'@pqc-sdk/core': minor
'@pqc-sdk/cli': minor
---

X-Wing is now a fully supported algorithm across the public API and CLI: `SUPPORTED_ALGORITHMS` includes `'x-wing'`, and `KEM_NAMES` is exported for introspection. `pqc keygen --algorithm x-wing` generates a hybrid key pair, and `pqc encrypt`/`pqc decrypt` accept either KEM key (`ml-kem-768` or `x-wing`) and write/read the matching envelope version automatically — `readKeyFile`'s expectation loosened from "exactly ml-kem-768" to "any KEM key," reporting the algorithm actually found on a mismatch. `pqc audit` migration hints now mention x-wing for long-term data. `pqc.keys.generate()` with no arguments is unchanged (`ml-kem-768`); the default flips to `x-wing` at v1.0 as previously announced.
