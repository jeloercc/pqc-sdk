---
'@pqc-sdk/core': patch
---

Fix: el export `version` ahora se inyecta en build time desde el `package.json`
del paquete, en vez de estar hardcodeado. Los bumps de changesets se reflejan
solos en ESM, CJS y los types.
