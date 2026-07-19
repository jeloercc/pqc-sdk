# Proposal: hybrid envelope v2 (X-Wing — X25519 + ML-KEM-768)

- **Status:** PROPOSAL — nothing in this document is implemented. The sprint
  starts only after this plan is approved.
- **Date:** 2026-07-19
- **Depends on:** `@pqc-sdk/core` 0.4.1 (envelope v1, `pqcv1` key tokens,
  golden-vector suite from PR #33)

## 1. Research: the state of hybrid KEMs (July 2026)

### X-Wing (chosen)

X-Wing is a general-purpose PQ/T hybrid KEM built from exactly the two
primitives we already ship — ML-KEM-768 and X25519 — with a fixed, analyzed
combiner. Current spec state:

- [`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
  is at **revision 10 (March 2026)**, intended status Informational (CFRG).
  Not yet an RFC, but the construction has been stable across many revisions
  and has a formal security analysis in the academic literature
  ([ePrint 2024/039, "X-Wing: The Hybrid KEM You've Been Looking For"](https://eprint.iacr.org/2024/039)).
- **Deterministic test vectors are published in Appendix C of the draft** —
  seeds, encapsulation keys, ciphertexts, and shared secrets — exactly what
  our KAT-first workflow needs.
- Fixed sizes: decapsulation key = **32-byte seed**, encapsulation key =
  **1216 bytes** (`pk_M(1184) ‖ pk_X(32)`), ciphertext = **1120 bytes**
  (`ct_M(1088) ‖ ct_X(32)`), shared secret = **32 bytes**.
- The combiner is `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` with the
  6-byte ASCII label `\.//^\`. Omitting `ct_M` from the hash is a deliberate,
  analyzed property that relies on ML-KEM's FO transform (draft §security
  considerations); it is safe **only** for this specific composition — which
  is precisely why we adopt the established combiner verbatim and design
  nothing ourselves.
- Key generation expands one 32-byte seed with `SHAKE-256` into 96 bytes:
  64 for `ML-KEM-768.KeyGen_internal`, 32 for the X25519 scalar. Secret-key
  storage and serialization stay tiny.

### IETF ECDHE-MLKEM (evaluated, not chosen)

[`draft-ietf-tls-ecdhe-mlkem-05`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
(May 2026) defines `X25519MLKEM768` and siblings **for TLS 1.3 key
agreement**: the two component secrets are concatenated and fed into the TLS
transcript-bound HKDF schedule. There is no standalone combiner to reuse
outside a TLS handshake — the domain separation comes from the TLS key
schedule itself. Adopting it for a self-contained file/message envelope would
mean inventing our own KDF wrapping, which violates our "never design our own
secret-mixing" rule. It remains the right reference for _naming_ awareness
(`X25519MLKEM768` is what browsers/TLS deploy), but X-Wing is the construction
designed for exactly our use case (a general-purpose KEM usable in HPKE-like
envelopes).

### What @noble provides (verified against our pinned versions)

Our **already-pinned** `@noble/post-quantum` **0.6.1** ships
`@noble/post-quantum/hybrid.js` with `ml_kem768_x25519` (exported alias
`XWing`), implementing the draft combiner (label `\.//^\`, hashing
`ss_M ‖ ss_X ‖ ct_X ‖ pk_X`), targeting draft-09 per its README
([noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)).
Verified empirically on our lockfile version today: `lengths = {seed: 32,
publicKey: 1216, secretKey: 32, cipherText: 1120}` and
keygen → encapsulate → decapsulate round-trips. `@noble/curves` (~2.2.0) is
already a transitive dependency of the pinned package — **no new top-level
dependency is required**.

Two verification gates before any envelope code (Day 1):

1. **Draft-09 vs draft-10 vector equivalence.** noble documents draft-09; the
   current draft is -10. Day 1 imports the Appendix C vectors from draft-10
   and runs them as KATs against noble 0.6.1. If any vector fails, the sprint
   pauses: we either bump the pin (deliberately, behind the vector tests, per
   policy) or hold the feature — we do not ship a combiner that disagrees
   with the current spec.
2. **API determinism.** The KAT harness must exercise deterministic
   encapsulation (noble's seeded `encapsulate(publicKey, seed)` path) so the
   vectors are checked byte-for-byte, not merely round-tripped.

## 2. The `pqcenc.v2` envelope format

### What v2 fixes cryptographically

v1 uses the raw ML-KEM-768 shared secret directly as the AES-256-GCM key
(`packages/core/src/encrypt.ts`). That is acceptable for a single-algorithm
format but is exactly the "direct use of the shared secret" pattern the June
audit flagged as a debt: no derivation step, no domain separation, nothing
binding the secret to the public context. In v2 the AES key is the X-Wing
combiner output — `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)` — i.e. a
spec-defined KDF with a fixed domain-separation label and binding to the
recipient public key, adopted exactly as the draft defines it. We add no
mixing, reordering, or extra inputs of our own.

### Byte layout

```
offset  size   field
0       1      format version byte: 0x02
1       1      algorithm header id: 0x02 (x-wing)
2       1120   X-Wing ciphertext  = ct_M (1088, ML-KEM-768) ‖ ct_X (32, X25519 ephemeral share)
1122    12     AES-256-GCM nonce (random per envelope)
1134    …      sealed payload (ciphertext ‖ 16-byte GCM tag)
```

Note one deliberate difference from the sprint sketch ("X25519 ephemeral key +
ML-KEM ciphertext"): X-Wing's ciphertext encoding is **`ct_M` first, then
`ct_X`** (draft §5.3). We store the X-Wing ciphertext as the opaque unit the
spec defines rather than re-ordering its parts — same never-invent rule
applied to encodings.

Unchanged from v1: AES-256-GCM as the AEAD, 12-byte random nonce, the 2-byte
header `(version, headerId)` bound as GCM additional authenticated data, and
the fail-fast header check backed by the AAD as the cryptographic guarantee.

### Key serialization

The `pqcv1.<algorithm>.<use>.<base64url>` token format is unchanged (the
token prefix `pqcv1` names the _token_ format, not the envelope version). New
algorithm value `x-wing`:

- `pqcv1.x-wing.public.<base64url of 1216 bytes>`
- `pqcv1.x-wing.secret.<base64url of 32-byte seed>`

Storing the secret key as the 32-byte X-Wing seed matches the draft's
decapsulation-key definition and keeps the CLI's key files small and format-
stable. CLI key files (`.public.pqc` / `.secret.pqc`, one token per line) are
unchanged structurally.

## 3. Compatibility contract

- **v1 ciphertexts remain decryptable forever.** `decrypt` dispatches on the
  version byte: `0x01` → the existing ML-KEM-768 path, `0x02` → X-Wing.
  Unknown versions keep failing with `INVALID_CIPHERTEXT`.
- **v1 golden vectors are untouched and must keep passing.** The golden-vector
  suite (PR #33) is the tripwire: any diff to the existing v1 fixtures fails
  the sprint. New **v2 golden vectors** are generated alongside them with
  `packages/core/scripts/generate-golden-vectors.mjs`.
- **`docs/serialization-format.md` gains the v2 layout** in the same PR that
  introduces it, per the serialization-stability rule.
- **Semver:** this is an _additive_ layout (a new version byte and algorithm
  id; no existing byte or token layout changes), so per the crypto-review
  rule's framing this is acknowledged as a **feature → minor bump**
  (0.5.0) for encrypt-side, with decrypt accepting both versions.
  Explicitly _not_ a major: nothing a v1-producing/consuming peer already
  does becomes invalid. Caveat documented in the changeset: peers still on
  ≤0.4.x cannot decrypt v2 envelopes or parse `x-wing` tokens — mixed-version
  fleets should upgrade readers before writers.

## 4. API proposal

### Choosing hybrid vs pure ML-KEM: by key, not by flag

`pqc.encrypt(data, publicKey)` keeps its exact signature and dispatches on
`publicKey.algorithm`: an `ml-kem-768` key produces a v1 envelope, an
`x-wing` key produces v2. No new options object, no mode flags — the key _is_
the choice, which also means a serialized key fully determines the format a
peer will receive.

### Default: `keys.generate()` flips to `x-wing` (recommendation)

Proposal: `pqc.keys.generate()` with no arguments generates `x-wing` in
0.5.0. Rationale:

- The project's hard rule is _zero-config = safe defaults_. The
  industry-consensus safe default for new deployments in 2026 is hybrid, not
  pure ML-KEM — TLS (`X25519MLKEM768` in Chrome/Firefox), Signal (PQXDH), and
  Apple (PQ3) all ship PQ/T hybrids so that a break of either component
  (including an ML-KEM implementation flaw) does not expose traffic.
- The cost is small now: we are pre-1.0 with a small adopter base, and
  `decrypt`/`deserialize` accept both algorithms, so every same-version
  deployment keeps working untouched.
- The risk is mixed-version fleets (a 0.5.0 writer with 0.4.x readers). The
  changeset, README, and migration note call this out; anyone needing the old
  behavior passes `{ algorithm: 'ml-kem-768' }` explicitly.

Fallback if the reviewer disagrees: ship `x-wing` opt-in in 0.5.0 and flip
the default in the next minor after an adoption window. The plan proceeds
identically either way; only one default constant and its docs differ.

### CLI

- `pqc keygen` gains `--algorithm x-wing` (and inherits whatever default the
  decision above lands on; key file naming defaults to the algorithm name as
  today).
- `pqc encrypt` accepts either KEM public key and writes the matching
  envelope version; `pqc decrypt` accepts either secret key and both envelope
  versions. `readKeyFile`'s expectation loosens from "exactly ml-kem-768" to
  "a KEM key" with the algorithm reported in errors as today.
- `pqc audit` migration hints start recommending `x-wing` for encryption.

## 5. Sprint plan (day-sized, each independently reviewable)

**Day 1 — combiner exposure + KAT gate (core, no format changes)**
Wire `x-wing` into `algorithms.ts` as a KEM spec backed by
`@noble/post-quantum/hybrid.js`'s `XWing`; import the draft-10 Appendix C
vectors as a KAT suite (deterministic keygen + seeded encapsulation,
byte-for-byte); extend key generate/serialize/deserialize property tests to
the new algorithm. **Gate:** all draft-10 vectors pass against the pinned
noble 0.6.1; any mismatch pauses the sprint for a deliberate pin decision.
Deliverable: PR with vectors + key plumbing only — no envelope changes, so
v1 golden vectors provably untouched.

**Day 2 — envelope v2 + goldens (core)**
`encrypt` dispatch on key algorithm; `decrypt` dispatch on version byte;
mutation-check tests tampering every v2 region independently (version byte,
header id, `ct_M`, `ct_X`, nonce, sealed payload, GCM tag) asserting the
documented `PqcError` codes, fail-closed; regenerate golden vectors additively
(v1 fixtures byte-identical, new v2 fixtures); update
`docs/serialization-format.md` (layout table, error taxonomy, version
negotiation rules). Deliverable: PR acknowledged as _additive minor_ per §3.

**Day 3 — API surface + CLI + docs (core + cli)**
`keys.generate` default decision wired + typed; CLI keygen/encrypt/decrypt
support; CLI interop tests (CLI↔SDK both directions, both versions, plus the
tamper-through-the-binary suite extended to v2); README + docs site + audit
hints; compatibility matrix rows stay honest (only runtimes with a real
executed roundtrip get ✅ for x-wing — rerun the Workers/Node targets, mark
the rest ⏳ per the compatibility rule); changesets (`minor` for core and cli,
linked) with the mixed-fleet caveat.

Estimated new public surface: one algorithm string, zero new functions.

## 6. Explicit non-goals

- No SLH-DSA, no signatures changes — this sprint is KEM/envelope only.
- No streaming envelope (tracked separately from the CLI 1 GiB guard).
- No custom combiner, KDF tweak, or encoding reordering under any
  circumstance: if X-Wing's draft changes incompatibly before we ship, the
  sprint pauses rather than "adjusting" the combiner locally.

## Sources

- [draft-connolly-cfrg-xwing-kem (datatracker, rev 10, March 2026)](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [draft-connolly-cfrg-xwing-kem-10 HTML (combiner, sizes, Appendix C vectors)](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html)
- [draft-ietf-tls-ecdhe-mlkem (datatracker, rev 05, May 2026)](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [X-Wing: The Hybrid KEM You've Been Looking For (ePrint 2024/039)](https://eprint.iacr.org/2024/039)
- [noble-post-quantum (hybrid module, draft-09 X-Wing)](https://github.com/paulmillr/noble-post-quantum)
- Local verification: `@noble/post-quantum@0.6.1` (pinned) `XWing` lengths and
  roundtrip, executed 2026-07-19 against this repo's lockfile.
