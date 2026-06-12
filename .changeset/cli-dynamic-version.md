---
'@pqc-sdk/cli': patch
---

Fix: la versión que muestra el CLI (`pqc --version` y el header de `--help`)
ahora se inyecta en build time desde el `package.json` del propio CLI, en vez
de estar hardcodeada. Los bumps de changesets se reflejan solos.
