---
'@pqc-sdk/core': patch
---

Add fast-check fuzzing for the `deserialize` parser, the SDK's primary attack
surface for untrusted input. The suite asserts a single fail-closed invariant
over thousands of hostile tokens — arbitrary/unicode/control-char strings,
wrong segment counts, unknown algorithms and uses, valid base64url of the wrong
length, off-by-one lengths, invalid and non-canonical base64url, the impossible
`% 4 === 1` length, truncated prefixes, and injected dots — across both the
untyped and typed (`{ algorithm, use }`) overloads: `deserialize` either returns
a structurally consistent key or throws a `PqcError`, never anything else.
Hand-picked regressions name the nastiest cases, and the truncation case covers
every prefix slice of a valid token. Test-only; no API or runtime change.
