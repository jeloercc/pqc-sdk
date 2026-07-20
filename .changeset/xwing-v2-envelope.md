---
'@pqc-sdk/core': minor
---

Hybrid envelope v2 (`pqcenc.v2`): `pqc.encrypt` with an `x-wing` public key now produces a v2 envelope (version byte `0x02`, X-Wing ciphertext `ct_M ‖ ct_X`, AES-256-GCM keyed by the draft's SHA3-256 combiner output used verbatim — see `docs/serialization-format.md` §2.2), and `pqc.decrypt` dispatches on the version byte, accepting both v1 and v2. The Day-1 `UNSUPPORTED_ALGORITHM` guard on x-wing keys is removed; `encrypt`/`decrypt` signatures widen to any KEM key. This is the additive layout change acknowledged in `docs/proposals/hybrid-envelope.md` §3: every v1 artifact remains valid and byte-identical (v1 golden vectors untouched), so no major bump. Caveat for mixed-version fleets: peers on ≤0.4.x cannot decrypt v2 envelopes — upgrade readers before writers.
