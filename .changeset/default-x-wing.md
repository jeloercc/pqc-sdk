---
'@pqc-sdk/core': minor
'@pqc-sdk/cli': minor
---

**BREAKING: `pqc.keys.generate()` with no arguments now returns an X-Wing hybrid pair (X25519 + ML-KEM-768), not pure ML-KEM-768.** The TypeScript overload changed from `Promise<KeyPair<'ml-kem-768'>>` to `Promise<KeyPair<'x-wing'>>`. **JavaScript consumers get no compile-time signal at all** — code calling `generate()` silently starts producing X-Wing keys, with different key sizes and a `pqcenc.v2` envelope. Anyone persisting keys from `generate()` must now decide deliberately. To keep the previous behaviour: `pqc.keys.generate({ algorithm: 'ml-kem-768' })`. Read [docs/MIGRATION-0.8.md](https://github.com/jeloercc/pqc-sdk/blob/main/docs/MIGRATION-0.8.md) before upgrading.

The CLI moves with it: `pqc keygen` with no `--algorithm` and `pqc init` development keys are now `x-wing`, so default key files are named `x-wing.public.pqc` / `x-wing.secret.pqc` rather than `ml-kem-768.*`. An SDK defaulting to hybrid while the CLI defaulted to pure would be worse than either consistent posture.

Why: a hybrid KEM survives the failure of either half, and ML-KEM-768 is young enough that a cryptanalytic result would leave a pure-PQ ciphertext with nothing to fall back on. This is the current consensus for new protocols — TLS 1.3's `X25519MLKEM768`, Signal's PQXDH, Apple's PQ3, and BSI and ANSSI recommendations. The flip was previously announced for v1.0; at 0.x the break is cheap and expected, and shipping the weaker default for longer was the worse trade.

**Pure ML-KEM-768 remains a first-class choice, not a legacy mode**, and is the right call in two cases: FIPS certification scope (X-Wing is a CFRG draft, not covered by FIPS 203, so a compliance regime requiring a certified KEM needs the pure one), and size or speed (32 bytes less per envelope; keygen 0.65 ms vs 1.56 ms, encrypt 1 KiB 0.80 ms vs 3.31 ms, decrypt 1 KiB 1.04 ms vs 3.38 ms on this repo's CI runner).

No serialized layout changed. `pqcenc.v1` and `pqcenc.v2` have coexisted since 0.5.0, `decrypt` dispatches on the version byte, and the golden vectors are untouched — every artifact produced by 0.7.x stays valid and decryptable. Mixed fleets: a peer on ≤0.4.x cannot read a `pqcenc.v2` envelope, so upgrade readers before writers, or pin writers to `ml-kem-768` until you can.
