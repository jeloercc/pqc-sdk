# Serialization format specification (normative)

This document is the normative spec for every serialized format
`@pqc-sdk/core` and `@pqc-sdk/cli` produce. **Stability guarantee: any key or
ciphertext produced by any published 0.3.x must deserialize correctly in every
future version.** Any change to these layouts is a breaking change requiring a
major version bump, an update to this document, and regenerated golden
vectors in the same PR (see "Golden vectors" below and
`.claude/rules/crypto-review.md`).

## 1. Key token (string)

```
pqcv1.<algorithm>.<use>.<base64url>
```

Four segments joined by `.` (exactly 3 dots — the base64url alphabet cannot
contain `.`):

| Segment   | Values                      | Notes                                  |
| --------- | --------------------------- | -------------------------------------- |
| version   | `pqcv1`                     | Literal prefix; the format's namespace |
| algorithm | `ml-kem-768` \| `ml-dsa-65` | FIPS 203 / FIPS 204                    |
| use       | `public` \| `secret`        |                                        |
| key bytes | base64url (see §5)          | Raw key bytes, no framing              |

Exact decoded byte lengths (also enforced on deserialize):

| Algorithm    | public | secret |
| ------------ | ------ | ------ |
| `ml-kem-768` | 1184   | 2400   |
| `ml-dsa-65`  | 1952   | 4032   |

Key bytes are the FIPS 203/204 encodings as produced by `@noble/post-quantum`
(`ek`/`dk` for ML-KEM, `pk`/`sk` for ML-DSA). `serialize(deserialize(t)) === t`
holds for every valid token (canonical encoding, locked by the golden tests).

## 2. Hybrid ciphertext (binary)

Output of `pqc.encrypt`, a single `Uint8Array`:

| Offset | Length         | Field                                                     |
| ------ | -------------- | --------------------------------------------------------- |
| 0      | 1              | Format version byte, `0x01`                               |
| 1      | 1              | Algorithm header id (`ml-kem-768` = `0x01`)               |
| 2      | 1088           | ML-KEM-768 ciphertext (FIPS 203 encapsulation)            |
| 1090   | 12             | AES-GCM nonce (random per message)                        |
| 1102   | plaintext + 16 | AES-256-GCM sealed payload (ciphertext ‖ 16-byte GCM tag) |

- Total length = **1118 + plaintext length**; anything shorter than 1118 is
  rejected as truncated.
- The 2-byte header `(version, headerId)` is bound as AES-GCM additional
  authenticated data: tampering with it fails the GCM tag even if the values
  are individually valid.
- The AES-256 key is the ML-KEM shared secret used directly (uniform per
  FIPS 203, no KDF), fresh per message.
- Header id values are reserved per algorithm; `0x01` = ml-kem-768. New
  algorithms take new ids; ids are never reused.

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
| Token with unknown use segment                    | `INVALID_SERIALIZED_KEY` |
| Token with invalid/non-canonical base64url        | `INVALID_SERIALIZED_KEY` |
| Token with wrong decoded key length               | `INVALID_KEY`            |
| Ciphertext shorter than 1118 bytes                | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown version byte (≠ `0x01`)   | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown header id (≠ `0x01`)      | `INVALID_CIPHERTEXT`     |
| Tampered ciphertext / wrong key (GCM tag failure) | `DECRYPTION_FAILED`      |

## 7. Forward compatibility

`pqcv1` tokens and version byte `0x01` are the only formats a v1 parser
understands. The contract for any future v2:

- A v1 parser MUST reject unknown version markers with the exact codes above
  — it must never misparse newer data. (This is today's behavior; the golden
  suite pins it.)
- A future v2 parser MUST keep accepting every v1 artifact (the golden
  vectors enforce this mechanically) and MUST reject versions it does not
  know with the same fail-closed posture.
- The `pqcv` string prefix and the leading version byte are the negotiation
  points; nothing else in either layout may be repurposed to signal versions.

## 8. Golden vectors

`packages/core/src/vectors/golden-serialization-v1.json` contains key tokens
for both algorithms and uses, a complete ciphertext with its expected
plaintext, and a signature with its message — all generated by the
**published** `@pqc-sdk/core@0.3.8` (key material derived from the fixed
seeds recorded in the file; ciphertext/signature bytes are inherently
non-reproducible and are themselves the committed artifact).
`src/golden-vectors.test.ts` deserializes and _uses_ them on every CI run.

To regenerate after a deliberate format change:
`pnpm --filter @pqc-sdk/core build && node scripts/generate-golden-vectors.mjs`
(from `packages/core`). Regeneration is only legitimate alongside a major
version bump acknowledged in the PR description.
