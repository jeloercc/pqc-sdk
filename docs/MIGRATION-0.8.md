# Migrating to 0.8.0 — the default KEM is now X-Wing

## Read this first: JavaScript consumers get no compile-time signal

`pqc.keys.generate()` with no arguments now returns an **X-Wing** hybrid pair
(X25519 + ML-KEM-768) instead of a pure **ML-KEM-768** pair. In TypeScript,
the no-argument overload changed from `Promise<KeyPair<'ml-kem-768'>>` to
`Promise<KeyPair<'x-wing'>>`, so an explicitly annotated variable will fail to
compile and show you exactly where to look.

**In plain JavaScript there is no such signal.** Code that calls
`pqc.keys.generate()` will silently start producing X-Wing keys — different
algorithm, different key sizes, and a `pqcenc.v2` envelope instead of
`pqcenc.v1` — with nothing failing at build time. If you persist keys
generated this way, or if anything downstream depends on the algorithm or the
byte sizes, **this is a decision you must now make deliberately** rather than
inherit.

To keep exactly the previous behaviour, pin it:

```ts
const pair = await pqc.keys.generate({ algorithm: 'ml-kem-768' });
```

That one line is the complete migration for anyone who wants 0.7.x behaviour.
It is a supported, first-class call — not a deprecation shim — and it is not
going away.

## What changed

|                                   | 0.7.x                | 0.8.0                |
| --------------------------------- | -------------------- | -------------------- |
| `keys.generate()` (no args)       | `ml-kem-768`         | **`x-wing`**         |
| Public key                        | 1184 B               | 1216 B               |
| Secret key                        | 2400 B               | 32 B (seed)          |
| Envelope written by `pqc.encrypt` | `pqcenc.v1` (`0x01`) | `pqcenc.v2` (`0x02`) |
| `pqc keygen` (no `--algorithm`)   | `ml-kem-768`         | **`x-wing`**         |
| `pqc init` development keys       | `ml-kem-768`         | **`x-wing`**         |

**No serialized layout changed.** `pqcenc.v1` and `pqcenc.v2` have coexisted
since 0.5.0, `pqc.decrypt` dispatches on the envelope's version byte, and the
golden vectors are untouched. Every artifact produced by 0.7.x remains valid
and decryptable. What changed is only which algorithm you get when you do not
choose one.

## Why the default moved

A hybrid KEM survives the failure of either half. ML-KEM-768 is a young
algorithm, and a cryptanalytic result against it would leave a pure-PQ
ciphertext with nothing to fall back on; X-Wing's X25519 half would still be
standing. The cost is small and the downside is asymmetric, which is why the
industry's current consensus for new protocols is hybrid: TLS 1.3's
`X25519MLKEM768`, Signal's PQXDH, Apple's PQ3, and explicit recommendations
from the BSI and ANSSI.

The SDK claims safe defaults. A safe default is the hybrid one.

## When to choose `ml-kem-768` instead

Pure ML-KEM-768 is **not** a legacy mode, and there are two good reasons to
pick it deliberately.

**FIPS certification scope.** ML-KEM-768 is standardised as FIPS 203. X-Wing
is a CFRG draft construction combining X25519 with ML-KEM-768, and it is _not_
covered by FIPS 203. If your compliance regime requires a certified KEM, pure
ML-KEM-768 is the correct choice, and choosing it is not a security compromise
— it is the standardised post-quantum KEM.

**Size and speed.** X-Wing costs 32 extra bytes per envelope and is meaningfully
slower. Measured on this repo's CI runner (`packages/core/bench/baseline.json`,
ubuntu24 / Node 20, mean ms per operation):

| Operation     | `ml-kem-768` | `x-wing` |
| ------------- | ------------ | -------- |
| keygen        | 0.65 ms      | 1.56 ms  |
| encrypt 1 KiB | 0.80 ms      | 3.31 ms  |
| decrypt 1 KiB | 1.04 ms      | 3.38 ms  |

For a high-volume path where envelopes are short-lived and the throughput
matters more than decades of confidentiality, that difference is a legitimate
engineering reason to keep the pure KEM. For data that must stay confidential
for years, it is not.

## Mixed fleets: upgrade readers before writers

A peer running **≤0.4.x cannot decrypt a `pqcenc.v2` envelope** or parse an
`x-wing` key token — those arrived in 0.5.0. If some of your fleet is older
than that, the default flip will produce envelopes they cannot read.

The order that works:

1. Upgrade every **reader** to ≥0.5.0 first (any 0.5+ release decrypts both v1
   and v2).
2. Then let **writers** move to 0.8.0 and start emitting v2.

If you cannot upgrade readers yet, pin writers to `{ algorithm: 'ml-kem-768' }`
until you can. This is a deployment-ordering constraint, not a reason to avoid
the upgrade.

## Checklist

- [ ] TypeScript: build and fix any explicit `KeyPair<'ml-kem-768'>` annotations
      — either accept `x-wing` or pin the algorithm.
- [ ] JavaScript: search for `keys.generate()` with no arguments and decide,
      per call site, whether hybrid is what you want.
- [ ] Persisted keys: existing ones keep working. New ones will be `x-wing`
      unless pinned.
- [ ] CLI scripts: `pqc keygen` with no `--algorithm` now writes
      `x-wing.public.pqc` / `x-wing.secret.pqc` rather than
      `ml-kem-768.*`. Pass `--algorithm ml-kem-768` or `--name` to keep the old
      file names.
- [ ] Readers on ≤0.4.x: upgrade them before writers, or pin writers.
