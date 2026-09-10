---
'@pqc-sdk/core': minor
---

`verify` now returns `false` for a wrong-length ML-DSA public key instead of throwing

FIPS 204 §3.6.2 makes the manner of the response part of the requirement: "If an
implementation of ML-DSA can accept inputs for σ or pk of any other length, it **shall
return false** whenever the lengths of either of these inputs differ from their lengths
specified in this standard."

The signature half already behaved this way — a wrong-length σ verifies to `false`. The
public-key half did not: `requireKey` threw `PqcError('INVALID_KEY')`, and it ran before
the try block in `verify`, so the rejection never reached the catch that would have
normalised it to `false`.

**Observable behaviour change.** Code that currently relies on the throw will break:

```ts
// Before: rejected with PqcError('INVALID_KEY')
// Now:    resolves to false
await pqc.verify(message, signature, { algorithm: 'ml-dsa-65', use: 'public', bytes });
```

Any `try`/`catch` around `pqc.verify` that treated `INVALID_KEY` as "the caller supplied a
mis-sized verification key" no longer fires for that case. A caller that already treated a
`false` result as "do not trust this signature" needs no change — the outcome is the same
answer delivered through the return value instead of an exception, and the behaviour was
fail-closed before and remains so.

**The change is scoped to `verify` only.** `requireKey` is unmodified, and every other
operation keeps the SDK-wide convention of throwing `INVALID_KEY` for a malformed key:
`encrypt`, `decrypt`, `sign`, `encryptStream`, `decryptStream` and the Web Stream variants
are untouched. A bad key there is an operator error with no meaningful "no" to return;
`verify` is the one operation whose contract is a boolean, and the one the standard names.

The carve-out covers **length only**. `verify` still throws for every other malformed-key
condition — `WRONG_ALGORITHM` for a non-ML-DSA key, `WRONG_KEY_USE` for a secret key passed
as public, `UNSUPPORTED_ALGORITHM` for an unknown algorithm — and still throws
`INVALID_CONTEXT` for a context string over 255 bytes.

Two regression tests were added to `sign.test.ts`: one covering five wrong public-key
lengths (0, 1951, 1953, and the 1312/2592 lengths that are _valid_ for ML-DSA-44 and
ML-DSA-87), mirroring the coverage that already existed for signature length; and one
pinning that the carve-out did not widen, so a future change relaxing `requireKey` globally
fails immediately.

No key, signature or envelope format changed. See `docs/compliance/FIPS-204-MATRIX.md`
§3.4 for the evidence and the row this closes (F204-08).
