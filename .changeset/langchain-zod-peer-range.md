---
'@pqc-sdk/langchain': patch
---

Narrow the `zod` peer range from `>=3.0.0` to `^3.25.1 || ^4.0.0`. The package imports `zod/v3`, which does not load before zod 3.25.1: zod 3.0–3.24 has no such entry point (`ERR_PACKAGE_PATH_NOT_EXPORTED`), and zod 3.25.0 declares it but ships without the file (`ERR_MODULE_NOT_FOUND`). npm installed the package next to those versions without a warning. The versions the new range excludes never worked, so nothing that worked before stops working.
