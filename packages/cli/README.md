# @pqc-sdk/cli

[![CI](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/jeloercc/pqc-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40pqc-sdk%2Fcli)](https://www.npmjs.com/package/@pqc-sdk/cli)

CLI for [@pqc-sdk/core](https://www.npmjs.com/package/@pqc-sdk/core):
post-quantum projects in one command.

```bash
# Initialize a project: config + development keys + working example
npx @pqc-sdk/cli init

# Generate keys serialized as base64url
npx @pqc-sdk/cli keygen --algorithm ml-dsa-65 --out keys/

# Detect pre-quantum crypto (RSA/ECDSA/ECDH) and what to migrate to PQC
npx @pqc-sdk/cli audit
```

`audit` exits with code 1 when it finds crypto to migrate — usable as a CI
gate. Output uses colors only when there is a TTY: readable in logs and pipes.

## License

[MIT](./LICENSE)
