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

# Heuristically detect pre-quantum crypto (RSA/ECDSA/ECDH) and what to migrate to PQC
npx @pqc-sdk/cli audit

# Encrypt a file for the holder of an ML-KEM-768 key pair…
npx @pqc-sdk/cli encrypt will.pdf --key keys/alice.public.pqc

# …and decrypt it with the matching secret key
npx @pqc-sdk/cli decrypt will.pdf.enc --key keys/alice.secret.pqc --out will.pdf
```

## encrypt / decrypt

`encrypt` seals a file into a self-contained envelope (ML-KEM-768 key
encapsulation + AES-256-GCM, the same format as `pqc.encrypt` in
[@pqc-sdk/core](https://www.npmjs.com/package/@pqc-sdk/core) — the two
interoperate in both directions). `decrypt` opens it with the matching secret
key and refuses corrupted or mismatched inputs instead of writing garbage.

```bash
pqc keygen --name alice                                  # keys/alice.{public,secret}.pqc
pqc encrypt report.pdf --key keys/alice.public.pqc       # report.pdf.enc
pqc decrypt report.pdf.enc --key keys/alice.secret.pqc   # report.pdf (0600)
```

Worth knowing:

- Output defaults: `encrypt` writes `<input>.enc`; `decrypt` strips the
  `.enc` (or appends `.dec`). Neither overwrites an existing file unless you
  pass `--force`.
- Decrypted plaintext is written readable only by you (mode 0600), and the
  CLI warns — without refusing — when a secret key file is readable by other
  users (fix with `chmod 600 <file>`).
- Files at or below 8 MiB are loaded fully into memory; larger files stream
  automatically (bounded memory regardless of size), up to a 1 TiB
  operational ceiling. No flag needed — the CLI picks the right path from the
  input size for `encrypt`, and from the ciphertext's own envelope header for
  `decrypt`.
- That 1 TiB ceiling is an **operational guard against accidental inputs**
  (pointing the CLI at a mounted block device, say) — not a cryptographic
  limit. The streaming envelope has no practical size bound of its own. Raise
  or lower it with `--max-size` on `encrypt`/`decrypt`:

  ```bash
  pqc encrypt archive.tar --key keys/alice.public.pqc --max-size 4TiB
  ```

  Accepts a byte count or a binary-unit size (`2TiB`, `500GiB`, `64MiB`).
  When `--max-size` actually admits a file the 1 TiB default would have
  refused, the CLI says so explicitly rather than proceeding quietly.

- Expected failures (missing file, wrong key, tampered envelope) print a
  one-line error on stderr and exit with code 1 — CI- and script-friendly.

`audit` is a best-effort regex scan of your dependencies and source: expect the
occasional false positive or false negative, and treat it as a starting point,
not a proof. Files larger than 1 MiB are skipped and reported. It exits with
code 1 when it finds crypto to migrate — usable as a CI gate. Output uses colors
only when there is a TTY: readable in logs and pipes.

## License

[MIT](./LICENSE)
