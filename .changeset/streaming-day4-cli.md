---
'@pqc-sdk/cli': minor
---

`pqc encrypt`/`pqc decrypt` now stream automatically for large files instead of refusing them: the old hard 1 GiB in-memory cap is gone, replaced by an 8 MiB cutover (at or below: the existing one-shot path; above: streaming, bounded memory regardless of file size) and a generous 1 TiB operational ceiling (a sanity check against accidental inputs, not a cryptographic limit — see `docs/proposals/streaming-encryption.md` §2). `pqc encrypt` picks the path from input size; `pqc decrypt` dispatches on the ciphertext's own envelope version byte, so a small streaming envelope (however it was produced) still decrypts correctly regardless of file size. On a failed streamed decrypt (tampered or truncated ciphertext), the partially-written output file is deleted rather than left on disk as a misleading result — the incremental-release property of `decryptStream` applied concretely.
