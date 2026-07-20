# Serialization format specification (normative)

This document is the normative spec for every serialized format
`@pqc-sdk/core` and `@pqc-sdk/cli` produce. **Stability guarantee: any key or
ciphertext produced by any published version must deserialize correctly in
every future version.** Any change to an existing layout is a breaking change
requiring a major version bump, an update to this document, and regenerated
golden vectors in the same PR (see "Golden vectors" below and
`.claude/rules/crypto-review.md`). Adding a _new_ version byte or algorithm
id alongside the existing ones — leaving every published layout byte-identical
and still accepted — is additive and ships as a minor (the path envelope v2
took, acknowledged in `docs/proposals/hybrid-envelope.md` §3).

## 1. Key token (string)

```
pqcv1.<algorithm>.<use>.<base64url>
```

Four segments joined by `.` (exactly 3 dots — the base64url alphabet cannot
contain `.`):

| Segment   | Values                                    | Notes                                  |
| --------- | ----------------------------------------- | -------------------------------------- |
| version   | `pqcv1`                                   | Literal prefix; the format's namespace |
| algorithm | `ml-kem-768` \| `ml-dsa-65` \| `x-wing`   | FIPS 203 / FIPS 204 / X-Wing draft     |
| use       | `public` \| `secret`                      |                                        |
| key bytes | base64url (see §5)                        | Raw key bytes, no framing              |

The `pqcv1` prefix names the _token_ format, not the envelope version — an
`x-wing` key serializes as a `pqcv1` token and produces v2 envelopes.

Exact decoded byte lengths (also enforced on deserialize):

| Algorithm    | public | secret |
| ------------ | ------ | ------ |
| `ml-kem-768` | 1184   | 2400   |
| `ml-dsa-65`  | 1952   | 4032   |
| `x-wing`     | 1216   | 32     |

Key bytes are the FIPS 203/204 encodings as produced by `@noble/post-quantum`
(`ek`/`dk` for ML-KEM, `pk`/`sk` for ML-DSA). `serialize(deserialize(t)) === t`
holds for every valid token (canonical encoding, locked by the golden tests).
X-Wing keys (draft-connolly-cfrg-xwing-kem-10 §5.2) are the draft encodings:
public = `pk_M(1184) ‖ pk_X(32)`, secret = the 32-byte seed that _is_ the
decapsulation key.

## 2. Hybrid ciphertext (binary)

Output of `pqc.encrypt`, a single `Uint8Array`. The envelope version is
selected by the public key's algorithm (`ml-kem-768` → v1, `x-wing` → v2);
`pqc.decrypt` discriminates on the leading version byte. **v1 remains valid
forever** — v2 does not replace it, and both versions are produced and
accepted side by side.

### 2.1 Envelope v1 (`0x01`, ml-kem-768)

| Offset | Length         | Field                                                     |
| ------ | -------------- | --------------------------------------------------------- |
| 0      | 1              | Format version byte, `0x01`                               |
| 1      | 1              | Algorithm header id (`ml-kem-768` = `0x01`)               |
| 2      | 1088           | ML-KEM-768 ciphertext (FIPS 203 encapsulation)            |
| 1090   | 12             | AES-GCM nonce (random per message)                        |
| 1102   | plaintext + 16 | AES-256-GCM sealed payload (ciphertext ‖ 16-byte GCM tag) |

- Total length = **1118 + plaintext length**; anything shorter than 1118 is
  rejected as truncated.
- The AES-256 key is the ML-KEM shared secret used directly (uniform per
  FIPS 203, no KDF), fresh per message.

### 2.2 Envelope v2 (`0x02`, x-wing)

| Offset | Length         | Field                                                     |
| ------ | -------------- | --------------------------------------------------------- |
| 0      | 1              | Format version byte, `0x02`                               |
| 1      | 1              | Algorithm header id (`x-wing` = `0x02`)                   |
| 2      | 1120           | X-Wing ciphertext = `ct_M(1088) ‖ ct_X(32)` (draft §5.4)  |
| 1122   | 12             | AES-GCM nonce (random per message)                        |
| 1134   | plaintext + 16 | AES-256-GCM sealed payload (ciphertext ‖ 16-byte GCM tag) |

- Total length = **1150 + plaintext length**; anything shorter than 1150 is
  rejected as truncated.
- The X-Wing ciphertext is stored as the opaque unit
  draft-connolly-cfrg-xwing-kem-10 §5.4 defines — `ct_M` (ML-KEM-768) first,
  then `ct_X` (X25519 ephemeral share) — never re-ordered or re-framed.
- The AES-256 key is the X-Wing shared secret used **verbatim**: the draft
  §5.3 combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` already
  is the key derivation, with a fixed domain-separation label and binding to
  the recipient public key. No additional KDF layer is applied on top.

### 2.3 Common to both versions

- The 2-byte header `(version, headerId)` is bound as AES-GCM additional
  authenticated data: tampering with it fails the GCM tag even if the values
  are individually valid.
- Header id values are reserved per algorithm; `0x01` = ml-kem-768,
  `0x02` = x-wing. New algorithms take new ids; ids are never reused.

## 3. Signature (binary)

Output of `pqc.sign`: the raw **3309-byte** ML-DSA-65 signature exactly as
FIPS 204 encodes it (hedged/randomized signing). No SDK framing, no version
byte — the format is owned by the standard, not by this SDK. The optional
signing context (≤ 255 bytes) is _not_ embedded; callers transport it
alongside the message.

## 4. CLI files on disk

- `<name>.public.pqc` / `<name>.secret.pqc`: the §1 key token followed by a
  single `\n`, UTF-8. Secret files are written with mode `0600`.
- `pqc.config.json`: `{ "defaultAlgorithm": "ml-kem-768", "keysDir": "keys" }`
  — tool configuration, not cryptographic material; not covered by the
  stability guarantee beyond ordinary semver.

## 5. base64url encoding

Unpadded base64url (RFC 4648 §5, alphabet `A–Z a–z 0–9 - _`, no `=`). The
decoder is strict: it rejects invalid characters, impossible lengths
(`length % 4 === 1`), and **non-canonical trailing bits** (the unused bits of
the final group must be zero), so every byte sequence has exactly one valid
encoding.

## 6. Error contract (fail closed)

What today's parsers do with malformed or unknown input — this is normative
behavior, locked by tests:

| Input                                             | `PqcError` code          |
| ------------------------------------------------- | ------------------------ |
| Token without 4 segments or prefix ≠ `pqcv1`      | `INVALID_SERIALIZED_KEY` |
| Token with unknown version prefix (e.g. `pqcv2`)  | `INVALID_SERIALIZED_KEY` |
| Token with unknown algorithm segment              | `UNSUPPORTED_ALGORITHM`  |
| Token with unknown use segment                            | `INVALID_SERIALIZED_KEY` |
| Token with invalid/non-canonical base64url                | `INVALID_SERIALIZED_KEY` |
| Token with wrong decoded key length                       | `INVALID_KEY`            |
| Ciphertext shorter than its version's minimum (§2)        | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown version byte (∉ `{0x01, 0x02}`)   | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown header id (∉ `{0x01, 0x02}`)      | `INVALID_CIPHERTEXT`     |
| Version/header id not matching the decrypting key         | `INVALID_CIPHERTEXT`     |
| Tampered ciphertext / wrong key (GCM tag failure)         | `DECRYPTION_FAILED`      |

The header check is relative to the secret key in use: a v1 envelope offered
to an `x-wing` key, or a v2 envelope offered to an `ml-kem-768` key, fails
fast with `INVALID_CIPHERTEXT` (cross-version key confusion never reaches the
KEM). Body tampering in either version — KEM ciphertext (`ct_M` or `ct_X`),
nonce, or sealed payload — surfaces as `DECRYPTION_FAILED`, never a raw
upstream error and never wrong plaintext.

## 7. Forward compatibility

`pqcv1` tokens and envelope version bytes `0x01`/`0x02` are the only formats
this parser understands. The contract, already exercised once by the v1 → v2
addition:

- **v1 artifacts remain valid forever.** The v2-capable parser keeps
  accepting every v1 envelope and token (the golden vectors enforce this
  mechanically); `decrypt` discriminates on the leading version byte.
- A parser MUST reject unknown version markers with the exact codes above —
  it must never misparse newer data. Parsers that predate v2 (≤ 0.4.x)
  already reject v2 envelopes and `x-wing` tokens fail-closed this way;
  mixed-version fleets must upgrade readers before writers.
- Any future version MUST follow the same pattern: keep accepting every
  older artifact, reject unknown versions fail-closed.
- The `pqcv` string prefix and the leading version byte are the negotiation
  points; nothing else in either layout may be repurposed to signal versions.

## 8. Golden vectors

Two fixture files, each locking the layouts that existed when it was
generated; the version suffix names the newest envelope it covers:

- `packages/core/src/vectors/golden-serialization-v1.json` — key tokens for
  `ml-kem-768` and `ml-dsa-65`, a complete v1 ciphertext with its expected
  plaintext, and a signature with its message — all generated by the
  **published** `@pqc-sdk/core@0.3.8`. Exercised by
  `src/golden-vectors.test.ts`. Regenerator:
  `scripts/generate-golden-vectors.mjs`.
- `packages/core/src/vectors/golden-serialization-v2.json` — `x-wing` key
  tokens and a complete v2 ciphertext with its expected plaintext, generated
  by the `@pqc-sdk/core` build that introduced envelope v2 (0.4.x + the v2
  changeset). Exercised by `src/golden-vectors-v2.test.ts`. Regenerator:
  `scripts/generate-golden-vectors-v2.mjs`.

In both files the key material derives from the fixed seeds recorded in the
file; ciphertext/signature bytes are inherently non-reproducible and are
themselves the committed artifact. The tests deserialize and _use_ them on
every CI run.

To regenerate after a deliberate format change:
`pnpm --filter @pqc-sdk/core build && node scripts/generate-golden-vectors.mjs`
(and/or `generate-golden-vectors-v2.mjs`) from `packages/core`. Regenerating
an **existing** fixture is only legitimate alongside a major version bump
acknowledged in the PR description; **adding** a new fixture file for a new
additive version (as v2 did) leaves the older files byte-identical and ships
as a minor.
