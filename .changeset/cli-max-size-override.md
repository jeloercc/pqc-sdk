---
'@pqc-sdk/cli': minor
---

`pqc encrypt`/`pqc decrypt` accept `--max-size` to raise or lower the 1 TiB operational size guard (a byte count or a binary-unit size such as `2TiB`, `500GiB`, `64MiB`). The default is unchanged at 1 TiB.

That guard is a sanity check against accidental inputs — pointing the CLI at a mounted block device, say — and never a cryptographic limit: the streaming envelope has no practical size bound of its own (`docs/serialization-format.md` §9.5). The help text and the refusal message both say so, and the refusal now names the flag that lifts it.

Bypassing the guard is explicit and loud: when `--max-size` admits a file the 1 TiB default would have refused, the CLI prints a warning naming the file size, the default, and the raised ceiling, rather than proceeding silently. Passing `--max-size` without actually crossing the default stays quiet.

Closes the deviation tracked in #54: `docs/proposals/streaming-encryption.md` §2 specified this ceiling as overridable, but 0.6.0 shipped it as a hard constant.
