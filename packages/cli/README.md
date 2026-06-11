# @pqc-sdk/cli

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcli)](https://www.npmjs.com/package/@pqc-sdk/cli)

CLI de [@pqc-sdk/core](https://www.npmjs.com/package/@pqc-sdk/core): proyectos
post-cuánticos en un comando.

```bash
# Inicializar proyecto: config + keys de desarrollo + ejemplo funcional
npx @pqc-sdk/cli init

# Generar keys serializadas en base64url
npx @pqc-sdk/cli keygen --algorithm ml-dsa-65 --out keys/

# Detectar crypto pre-cuántico (RSA/ECDSA/ECDH) y qué migrar a PQC
npx @pqc-sdk/cli audit
```

`audit` sale con código 1 si encuentra crypto a migrar — usable como gate de CI.
El output usa colores solo cuando hay TTY: legible en logs y pipes.

## Licencia

[MIT](./LICENSE)
