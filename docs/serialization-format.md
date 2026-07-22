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

| Segment   | Values                                  | Notes                                  |
| --------- | --------------------------------------- | -------------------------------------- |
| version   | `pqcv1`                                 | Literal prefix; the format's namespace |
| algorithm | `ml-kem-768` \| `ml-dsa-65` \| `x-wing` | FIPS 203 / FIPS 204 / X-Wing draft     |
| use       | `public` \| `secret`                    |                                        |
| key bytes | base64url (see §5)                      | Raw key bytes, no framing              |

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

| Input                                                   | `PqcError` code          |
| ------------------------------------------------------- | ------------------------ |
| Token without 4 segments or prefix ≠ `pqcv1`            | `INVALID_SERIALIZED_KEY` |
| Token with unknown version prefix (e.g. `pqcv2`)        | `INVALID_SERIALIZED_KEY` |
| Token with unknown algorithm segment                    | `UNSUPPORTED_ALGORITHM`  |
| Token with unknown use segment                          | `INVALID_SERIALIZED_KEY` |
| Token with invalid/non-canonical base64url              | `INVALID_SERIALIZED_KEY` |
| Token with wrong decoded key length                     | `INVALID_KEY`            |
| Ciphertext shorter than its version's minimum (§2)      | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown version byte (∉ `{0x01, 0x02}`) | `INVALID_CIPHERTEXT`     |
| Ciphertext with unknown header id (∉ `{0x01, 0x02}`)    | `INVALID_CIPHERTEXT`     |
| Version/header id not matching the decrypting key       | `INVALID_CIPHERTEXT`     |
| Tampered ciphertext / wrong key (GCM tag failure)       | `DECRYPTION_FAILED`      |

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

## 9. Streaming envelope (binary)

Output of `pqc.encryptStream` (`docs/proposals/streaming-encryption.md`): an
`AsyncIterable<Uint8Array>` whose concatenated bytes form the layout below.
Chosen so multi-GB payloads never need to be held in memory at once — see
the proposal for the full research and design rationale. **Independent of
§2's one-shot envelopes**: `pqc.encrypt`/`pqc.decrypt` neither produce nor
accept these bytes, and vice versa; v1/v2 stay byte-identical forever.

### 9.1 Version bytes

Same `pqcenc` version-byte space as §2, two new values:

| Version byte | KEM          | Header id |
| ------------ | ------------ | --------- |
| `0x03`       | `ml-kem-768` | `0x01`    |
| `0x04`       | `x-wing`     | `0x02`    |

**Recorded consequence of this choice** (2026-07-22 proposal review): coupling
envelope-shape to KEM means every future KEM costs **two** version bytes, not
one — a one-shot id and a streaming id. That's fine at KEM count 2. If the
number of supported KEMs ever grows past a handful, a future format revision
may need to decouple envelope-shape from KEM (e.g. a single "streaming"
version byte with the KEM carried only in the header id, as the header id
already does today for one-shot). Documented now as a recorded decision with
a known scaling limit, not something a future contributor rediscovers by
accident.

### 9.2 Header (fixed, once per stream)

| Offset | Length       | Field                                                     |
| ------ | ------------ | --------------------------------------------------------- |
| 0      | 1            | Version byte: `0x03` or `0x04` (§9.1)                     |
| 1      | 1            | Algorithm header id: `0x01`/`0x02`, same values as §2     |
| 2      | 1            | Chunk-size exponent `e`: chunk size = 2^e plaintext bytes |
| 3      | 1088 or 1120 | KEM ciphertext, same encoding as the one-shot envelope    |

`e` MUST be in `0..=24` inclusive (1 byte..16 MiB plaintext per chunk); `e`
outside that range is rejected as `INVALID_CIPHERTEXT` before any
cryptographic work. There is no floor beyond `0` — unlike the ceiling, a
minimum chunk size is not a cryptographic requirement (the nonce scheme in
§9.3 is sound at any positive chunk size), only a usability guardrail, and
one that would conflict with using a small `e` for compact golden-vector
fixtures (§8). The default `e` used by `pqc.encryptStream` is `16`
(64 KiB, matching age's STREAM default) — "safe defaults always" is
satisfied by the default, not by restricting the advanced option. No random
nonce field is stored
here (unlike §2's one-shot envelope) — chunk nonces are fully deterministic
from position (§9.3), and the KEM shared secret is fresh per stream
(a new `encapsulate()` per `encryptStream` call), so there is no reuse risk
for header randomness to defend against.

### 9.3 Chunk framing

For chunk index `i` (0-based, `bigint`, starting at 0) with plaintext `P_i`:

- **Nonce** (12 bytes): `BE88(i) ‖ flag` — an 11-byte big-endian encoding of
  `i`, followed by a 1-byte flag: `0x00` for every chunk except the last,
  which gets `0x01`. This is age's STREAM nonce
  (`github.com/C2SP/C2SP/blob/main/age.md`, "Payload"), adopted verbatim.
- **AAD**: the 3-byte header (`version ‖ headerId ‖ e`, §9.2) — identical on
  every chunk, so tampering with the declared parameters breaks
  authentication on chunk 0 immediately.
- **Ciphertext**: `AES-256-GCM(key = KEM shared secret, nonce, aad).seal(P_i)`
  → `len(P_i) + 16` bytes (16-byte GCM tag).

Non-final chunks MUST be exactly `2^e` plaintext bytes on the wire
(`2^e + 16` bytes); the final chunk is `0` to `2^e` plaintext bytes
(`16` to `2^e + 16` wire bytes). There is no explicit chunk-count or length
field — a decoder infers chunk boundaries from how many bytes a read
returns (Tink's "non-final segments are max length" rule).

**Decoding is not simply "trust the flag."** The flag is never transmitted
separately — it only exists inside a nonce a decoder must itself choose
before attempting decryption, so a decoder reading exactly `2^e + 16` bytes
with no more input immediately following cannot tell, from length alone,
whether it has a genuine full-size final chunk or a truncated non-final one
(both produce the same byte count). The normative decode algorithm resolves
this the only safe way — by attempting decryption, not by guessing from
length:

1. Read up to `2^e + 16` bytes. If the source is exhausted before that many
   bytes are available, this is unambiguously the final chunk (nothing else
   could still be missing): decrypt with `flag = 0x01`. Failure at this step
   is `DECRYPTION_FAILED` — the stream is truncated or tampered.
2. If exactly `2^e + 16` bytes were read, first attempt decryption with
   `flag = 0x00` (the common case: this chunk is non-final).
   - **Success** → yield the plaintext, advance to chunk `i+1`, and repeat
     from step 1. If step 1 later finds the source _already_ exhausted
     (zero further bytes) despite the most recent chunk having decrypted as
     non-final, that is truncation: `DECRYPTION_FAILED` — a stream may only
     end after a chunk that authenticated with `flag = 0x01`.
   - **Failure** → attempt decryption of the _same_ `2^e + 16` bytes with
     `flag = 0x01` (this chunk may genuinely be a full-size final chunk).
     Success → yield the plaintext, then read one more byte to confirm the
     source is truly exhausted; any further byte is trailing data appended
     after a legitimate stream end and is rejected as `DECRYPTION_FAILED`
     (an extension attack). Failure of both attempts → `DECRYPTION_FAILED`.

Every failure path above surfaces as `DECRYPTION_FAILED`, never a raw
upstream error, per `.claude/rules/crypto-review.md`'s error-contract rule.

**Incremental-release property.** `pqc.decryptStream` yields each plaintext
chunk as soon as that specific chunk authenticates — each yielded chunk is
genuinely authentic on its own, but "the whole plaintext is authentic and
complete" is signaled only by the async iterable finishing without
throwing, never by any individual yield. A truncated stream can yield one or
more genuine prefix chunks before the iterable throws (see the decode
algorithm above: a chunk that authenticates with `flag = 0x00` is real
output, emitted before its successor is even read). Consumers writing
decrypted output anywhere observable (a file, a socket) must treat that
output as provisional until the iterable completes cleanly. This is
structural to streaming/online AEAD, not a shortcut specific to this
implementation — age has the same property.

### 9.4 Overhead

- Per chunk: 16 bytes (GCM tag) — ≈0.024% at the 64 KiB default.
- Per stream (once): 3-byte header + KEM ciphertext (1088 B `ml-kem-768`,
  1120 B `x-wing`).

### 9.5 Maximum stream size

Not bounded by the cryptography in any practical sense: the 11-byte counter
gives a `2^88` chunk-index space, and — unlike constructions with a
long-lived master key — the AES-256-GCM key here is never reused across
streams (a fresh KEM `encapsulate()` per `encryptStream` call), so there is
no "total bytes under one key" ceiling to manage. `pqc.encryptStream` throws
`STREAM_OVERFLOW` if the chunk index would exceed `2^88 - 1`, a purely
defensive bound never reachable by any realistic input. Operational ceilings
(e.g. the CLI's, `docs/proposals/streaming-encryption.md` §2) are a
CLI-level sanity check against operator mistakes, not a cryptographic
requirement of this format.
