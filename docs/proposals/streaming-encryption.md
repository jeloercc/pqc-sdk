# Proposal: streaming encryption (chunked AEAD for large payloads)

- **Status:** PROPOSAL — nothing in this document is implemented. The sprint
  starts only after this plan is approved.
- **Date:** 2026-07-22
- **Depends on:** `@pqc-sdk/core` 0.5.0 (envelope v1/v2, both KEMs public —
  see `docs/proposals/hybrid-envelope.md`)

## 0. The problem

`pqc.encrypt`/`pqc.decrypt` (`packages/core/src/encrypt.ts`) load the entire
payload into memory: one `Uint8Array` in, one `Uint8Array` out, one AES-GCM
call. That's why the CLI has a hard wall — `packages/cli/src/input.ts:12`
sets `MAX_INPUT_BYTES = 1 GiB` and `input.ts:25-36` (`assertReadableInput`)
refuses anything larger with:

> `<path> is <N> GiB, above the 1 GiB limit: the CLI loads the whole file
> into memory (no streaming yet). Split the file or encrypt an archive of
> its parts.`

Multi-GB files (backups, disk images, media) need multi-GB RAM under the
current design, or the CLI simply refuses them. This proposal adds a chunked
encryption path that bounds memory to roughly one chunk, independent of
payload size.

## 1. Research: established streaming/chunked AEAD constructions (July 2026)

The failure mode this whole space exists to prevent is **naive chunking**:
split the plaintext, AEAD-seal each piece with the same key and a random or
reused nonce, concatenate. That's trivially breakable — chunks can be
dropped (truncation), swapped (reordering), or spliced from a different
message (chunk-swap), and the AEAD tags on the surviving chunks still verify
individually, because nothing binds a chunk to its *position in this
specific stream*. Every credible construction solves exactly this by folding
the chunk's position and finality into what the AEAD authenticates — as a
KDF-derived nonce, an explicit AAD field, or both. We adopt one of these
verbatim, for the same reason the X-Wing combiner was adopted verbatim
(`.claude/rules/crypto-review.md`'s combiner-discipline rule): the chunk
framing is exactly where naive designs die, so it is not a place to
improvise.

### STREAM (Hoang, Reyhanitabar, Rogaway, Vizár — foundational)

["Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"](https://eprint.iacr.org/2015/189),
CRYPTO 2015. Defines "online AEAD" formally and the STREAM construction:
segment a message, derive each segment's AEAD nonce deterministically from a
**per-message key/nonce, the segment index, and a final-segment bit**, and
prove that this online encryption scheme achieves nonce-based AEAD security
even though segments are processed one at a time. This is the theoretical
basis every deployed construction below implements a variant of — the
"index + finality inside the nonce" idea is not a folk convention, it is
the specific property the security proof is built on.

### age (chosen as our template)

[age's payload encryption](https://github.com/C2SP/C2SP/blob/main/age.md) is
a direct, widely-deployed, audited STREAM instantiation:

- 64 KiB plaintext per chunk; the final chunk may be shorter (1–64 KiB), or
  exactly empty if the whole payload is empty.
- ChaCha20-Poly1305, 12-byte nonce = **11-byte big-endian chunk counter
  (starting at 0) ‖ 1-byte flag** (`0x00` = more chunks follow, `0x01` =
  this is the final chunk).
- No explicit chunk-count or length field in the format. A reader knows a
  chunk is final only by the flag bit *and* must error if input ends without
  ever having authenticated a `0x01`-flagged chunk — that second half is
  what actually stops truncation (see §5).

### Tink Streaming AEAD (AES-GCM-HKDF-STREAMING)

[Google Tink's framing](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming):
a per-file header (`len(Header) ‖ Salt ‖ NoncePrefix`) feeds HKDF to derive a
per-file key from a long-lived master key; each segment's nonce is
`NoncePrefix ‖ segmentIndex(4B BE) ‖ finalByte`. Two details worth
borrowing regardless of construction: **non-final segments are required to
be the maximum allowed length** (so segment boundaries are self-evident from
bytes read, no length field needed), and the header carries the parameters
needed to decrypt without out-of-band coordination.

### libsodium `crypto_secretstream_xchacha20poly1305` (alternative model, not chosen)

[Encrypted streams](https://jedisct1.gitbooks.io/libsodium/content/secret-key_cryptography/secretstream.html):
state-machine API with an encrypted **tag byte** per message
(`TAG_MESSAGE`/`TAG_PUSH`/`TAG_REKEY`/`TAG_FINAL`) folded into the AEAD
input, and transparent rekeying before the internal counter wraps. Elegant,
but it's a stateful-session API shape (push/pull on a long-lived state
object), not a self-contained byte format — a worse fit for "one call in,
one deserializable envelope out," which is the shape `pqc.encrypt` already
has. We take the "authenticate the framing metadata, don't trust the
attacker's copy of it" lesson from it, not the API shape.

### IETF: `draft-sullivan-cfrg-raae` (informational, in progress — not depended on)

[draft-sullivan-cfrg-raae-02](https://datatracker.ietf.org/doc/draft-sullivan-cfrg-raae/02/)
("Random-Access Authenticated Encryption", rev 02, expires 2027-01-14, **no
IETF standing yet**) explicitly generalizes Tink Streaming AEAD and OpenPGP
v2 SEIPD as deployed STREAM-family formats, and formalizes the same pattern
this proposal uses: "derive a message key and nonce prefix from a key and
salt, encrypt each chunk under an AEAD nonce carrying the chunk index, and
detect truncation with a final tag." We cite it as evidence the pattern is
converging into a real standardization effort, not as a dependency — it's
an active draft, not something to build against yet, and it targets a much
larger problem (in-place random-access rewrites with snapshot attestation)
than sequential streaming encryption.

### Comparison

| | Nonce/binding | Chunk size | Per-chunk overhead | Format self-describes params |
|---|---|---|---|---|
| STREAM (paper) | index + final bit in nonce, formally proven | scheme-defined | AEAD tag only | n/a (it's the model, not a wire format) |
| age | 11B counter + 1B flag in nonce | fixed 64 KiB | 16B (Poly1305 tag) | No — fixed by spec, no header params |
| Tink AES-GCM-HKDF | noncePrefix ‖ 4B index ‖ flag; AAD empty | configurable | 16B (GCM tag) | Yes — header carries salt + noncePrefix |
| libsodium secretstream | internal state counter + encrypted tag byte | app-chosen | 17B (tag + 1B tag byte) | No — session parameters, not in a byte format |

**Chosen approach:** age's exact nonce/framing pattern (11-byte BE counter +
1-byte final flag, fixed/max-length non-final chunks, error-on-EOF-without-final),
reusing the AES-256-GCM primitive (`@noble/ciphers/aes.js` `gcm()`) already
in `packages/core/src/encrypt.ts` — no new dependency, no new construction.
One deliberate deviation from age, borrowed from Tink instead: age hardcodes
64 KiB and stores no parameters in its header because it's a single fixed
format; we want a configurable chunk size (§3) while staying self-describing
(so a stream never needs out-of-band coordination to decrypt), so the chunk
size is a header field, authenticated the same way the version/algorithm
header already is.

One thing we deliberately do **not** add: age and Tink both derive their
per-file/per-stream key via HKDF from a master key, because their master key
is long-lived and reused across many files. Ours isn't — every stream's key
is a KEM shared secret from a fresh `encapsulate()` call, single-use by
construction, exactly like v1/v2's one-shot key today. Inserting an HKDF
step here would be adding a KDF layer with no freshness problem to solve,
which is exactly what the combiner-discipline rule warns against. The
shared secret is used directly as the AES-256 key, unchanged from v1/v2.

## 2. Format proposal

### Relation to v1/v2

Same `pqcenc` envelope family, **new version bytes**, not a separate format:
`0x03` = ml-kem-768 streaming, `0x04` = x-wing streaming. This mirrors the
existing pattern exactly (`0x01`/`ml-kem-768` and `0x02`/`x-wing` for
one-shot) rather than inventing a new discrimination mechanism — the header
id byte keeps meaning "which KEM" (`0x01`/`0x02`, reused, never reassigned,
per `docs/serialization-format.md` §2.3), and the version byte now also
carries "which envelope shape." `pqc.encrypt`/`pqc.decrypt` are completely
unaware these bytes exist — they keep rejecting `0x03`/`0x04` with the
existing `INVALID_CIPHERTEXT` "unknown version" path, and the new
`encryptStream`/`decryptStream` (§3) keep rejecting `0x01`/`0x02` the same
way. **v1 and v2 golden vectors stay byte-identical forever** — this is
additive, ships as a minor (0.6.0), matching the v1→v2 precedent
acknowledged in `docs/proposals/hybrid-envelope.md` §3.

### Header (fixed, once per stream)

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | Version byte: `0x03` (ml-kem-768) or `0x04` (x-wing) |
| 1 | 1 | Algorithm header id: `0x01`/`0x02`, same values as one-shot |
| 2 | 1 | Chunk-size exponent `e`: chunk size = 2^e plaintext bytes |
| 3 | 1088 or 1120 | KEM ciphertext (same encoding as the one-shot envelope) |

`e` is bounds-checked on decode to a documented safe range — proposed
`10..=24` (1 KiB..16 MiB plaintext per chunk); the CLI/SDK default is
`e = 16` (64 KiB, matching age). The 3-byte header prefix
(`version ‖ headerId ‖ e`) is bound as AES-GCM AAD on **every** chunk
(§"Chunk framing" below), so a corrupted or attacker-flipped chunk-size byte
fails the very first chunk's tag rather than silently shifting chunk
boundaries.

No random nonce is stored in the header (unlike v1/v2, which store one
random 12-byte nonce). It isn't needed: chunk nonces are fully deterministic
from position (below), and the KEM shared secret is already fresh per
stream, so there is no reuse risk to defend against with header randomness.

### Chunk framing

For chunk index `i` (0-based) with plaintext `P_i`:

- **Nonce** (12 bytes): `BE88(i) ‖ flag`, where `flag = 0x00` for every
  chunk except the last, which gets `0x01`. (`BE88` = 11-byte big-endian —
  age's exact scheme.)
- **AAD**: the 3-byte header (`version ‖ headerId ‖ e`) — identical AAD on
  every chunk, so tampering with the declared parameters breaks
  authentication on chunk 0 immediately.
- **Ciphertext**: `AES-256-GCM(key = KEM shared secret, nonce, aad).seal(P_i)`
  → `len(P_i) + 16` bytes.

Non-final chunks MUST be exactly `2^e` plaintext bytes (so `2^e + 16` bytes
on the wire); the final chunk is `0` to `2^e` plaintext bytes (`16` to
`2^e + 16` wire bytes) — Tink's "non-final segments are max length" rule,
which is what lets a decoder infer chunk boundaries purely from how many
bytes a read returns, with no explicit length or count field.

### Overhead

- Per chunk: 16 bytes (GCM tag) — at the 64 KiB default, ≈0.024%.
- Per stream (once): 4-byte header + KEM ciphertext (1088 B ml-kem-768,
  1120 B x-wing) — identical to one-shot's per-message KEM cost, just no
  extra 12-byte nonce field.

### Maximum stream size

Effectively unbounded by the cryptography, not just "generous": the 11-byte
counter has a `2^88` chunk-index space, and — unlike age or Tink — the
AES-256-GCM key is **never reused across streams** (fresh KEM `encapsulate()`
per stream), so there is no "total bytes under one key" ceiling to manage
the way long-lived-master-key designs need one. NIST SP 800-38D's
`2^39 - 256`-bit (~64 GiB) limit is a *per-(key, nonce) invocation* bound on
plaintext length — irrelevant here since each chunk is at most 16 MiB. We
still propose the CLI enforce a generous, overridable **operational**
ceiling (default 1 TiB) as a sanity check against operator mistakes (e.g.
pointing it at a block device), clearly documented as a CLI safety net, not
a cryptographic requirement.

## 3. API proposal

### Core primitive: async iterables, not a host Streams API

The hard constraint is "works on ALL supported runtimes" — and per
`.claude/rules/crypto-review.md`'s honest-compatibility rule, "works" means
actually verified, not assumed. `docs/compatibility.md` already tracks Node,
Deno, Cloudflare Workers, and Hermes/React Native separately because their
host capabilities genuinely differ:

- Node 20+ and Deno ship the WHATWG Streams API (`ReadableStream`,
  `TransformStream`) natively.
- Cloudflare Workers (workerd) implements the Streams Standard natively too
  — and today's compatibility doc specifically notes x-wing needs **no**
  `nodejs_compat` flag; a Web-Streams-only design would preserve that.
- Hermes/React Native's Streams API support is not established fact here —
  nothing in this repo has verified `ReadableStream`/`TransformStream` on
  Hermes, and issue #45 shows we're still catching up on verifying even
  *existing* algorithms on that engine. Building the only public API on an
  unverified host feature would be a new compatibility gap on day one.

Async iteration (`for await`, async generators) is plain ECMAScript, not a
host API — it needs nothing from the runtime beyond the language itself, so
it is the one primitive we can honestly claim works identically everywhere
without first running a device test. Proposed core:

```ts
function encryptStream(
  publicKey: PublicKey<KemAlgorithm>,
  plaintext: AsyncIterable<Uint8Array>,
  options?: { chunkSize?: number },
): AsyncIterable<Uint8Array>;

function decryptStream(
  secretKey: SecretKey<KemAlgorithm>,
  ciphertext: AsyncIterable<Uint8Array>,
): AsyncIterable<Uint8Array>;
```

`chunkSize` is the one advanced option (defaults to 64 KiB, satisfying
"zero-config API: safe defaults always"); everything else mirrors
`encrypt`/`decrypt`'s existing signatures. Input chunk boundaries from the
caller's iterable don't need to match the wire chunk size — the
implementation buffers and re-chunks internally, the same way any of the
reference constructions do.

### Ergonomic adapters (thin, not the core surface)

- `encryptWebStream`/`decryptWebStream`: wrap the async-iterable core as a
  `TransformStream`, for Node/Deno/Workers pipeline ergonomics
  (`readable.pipeThrough(...)`). A few lines over the core primitive, no
  independent crypto logic.
- Node convenience: no new adapter code needed — `Readable` already *is*
  `AsyncIterable<Buffer>` (`for await` works directly on
  `fs.createReadStream(...)`), and `Readable.toWeb`/`Writable.fromWeb` are
  built into Node 20+ for bridging to the Web Streams adapters above. No new
  dependency either way.
- Hermes/RN: consume the async-iterable core directly. Stays whatever the
  compatibility doc says once actually run (§4) — no claim made here beyond
  "plain async generators are part of the language."

### CLI

Replace the hard 1 GiB wall (`packages/cli/src/input.ts:12,25-36`) with a
threshold: inputs at or below a small cutover (proposed 8 MiB) keep using
the existing one-shot `pqc.encrypt`/`decrypt` (v1/v2) — it's simpler,
already battle-tested, and the RAM cost is negligible at that size. Above
the cutover, `encrypt`/`decrypt` commands switch to
`fs.createReadStream`/`createWriteStream` piped through
`encryptStream`/`decryptStream` (v3/v4), bounding CLI memory to
`O(chunkSize)` regardless of file size, up to the operational ceiling in §2.
The `--algorithm`/key-file plumbing added in the hybrid sprint (`ml-kem-768`
or `x-wing`) carries over unchanged — the streaming path picks its version
byte from the same key algorithm check `readKemKeyFile` already does.

## 4. Compatibility contract

- **v1/v2 untouched, forever.** Nothing in this proposal changes
  `encrypt.ts`'s existing code path, its byte layout, or its golden vectors.
  `pqc.encrypt`/`pqc.decrypt` don't gain new parameters; streaming is
  additive functions, not a mode flag on the existing ones.
- **New golden vectors**: `packages/core/src/vectors/golden-serialization-streaming.json`
  (self-describing name, avoids clashing with envelope version bytes
  `0x03`/`0x04` vs. "vector file v3"), generated by a new
  `scripts/generate-golden-vectors-streaming.mjs`, exercised by
  `src/golden-vectors-streaming.test.ts`. Uses a small `chunkSize` (e.g. 8
  bytes) so a multi-chunk fixture stays compact, covering both `ml-kem-768`
  and `x-wing` from day one.
- **`docs/serialization-format.md`**: new `§9 Streaming envelope` appended
  (header layout, chunk framing, nonce/AAD construction, the `2^e` chunk-size
  encoding and its bounds) — additive to the document, no existing section
  edited except the table of contents.
- **Mutation tests** (`.claude/rules/crypto-review.md`'s mutation-check
  rule, applied to chunk boundaries specifically):
  - **Truncation, mid-chunk**: cut ciphertext inside a sealed chunk →
    `DECRYPTION_FAILED` (short read, GCM tag can't even be checked/fails).
  - **Truncation, chunk-aligned (the dangerous case)**: drop the entire
    final chunk, so the stream ends exactly on a non-final chunk boundary →
    must still fail. This is the case naive designs miss: every remaining
    chunk verifies individually. The decoder must track "have I
    authenticated a `flag=0x01` chunk yet?" and error on EOF if not —
    exactly age's documented rule, and the one to write first.
  - **Reorder**: swap chunk `i` and `i+1` → chunk `i`'s ciphertext, now read
    at position `i+1`, is opened against nonce index `i+1` (the decoder's
    own position counter, never attacker-supplied) instead of the index
    `i` it was actually sealed under → tag mismatch → `DECRYPTION_FAILED`.
  - **Duplicate/insert**: repeat chunk `i` → the decoder's position counter
    advances past what the repeated ciphertext was sealed under → same
    failure mode as reorder.
  - **Swap across streams**: splice chunk `i` from ciphertext A into
    ciphertext B at the same position → different KEM shared secret ⇒
    different key ⇒ tag mismatch regardless of position/nonce correctness.
    Worth its own explicit test even though it's implied by the above,
    because it's the concrete attack "swap" usually means.
  - **Final-flag games**: flip a non-final chunk's flag bit, or clear the
    true final chunk's flag bit → nonce the decoder computes (from its own
    position + its own read-size-derived finality, never from a bit the
    attacker controls) diverges from the one used to seal → tag mismatch.
  - **Edge cases**: empty plaintext (single empty final chunk, mirroring
    age's convention), plaintext exactly divisible by chunk size (does the
    final chunk correctly come out empty rather than omitted or duplicated),
    single-byte plaintext.
  - Every failure above must surface as the documented `PqcError` code
    (`DECRYPTION_FAILED` / `INVALID_CIPHERTEXT` as appropriate) — never a
    raw upstream `@noble` error, never silently-truncated plaintext.
  - All of the above run against **both** `ml-kem-768` and `x-wing` streams
    from day one, not just one KEM with the other assumed to follow the
    same code path.
- **Compatibility doc**: `docs/compatibility.md` gets streaming rows
  starting at ⏳ across the board, same honest-by-default posture x-wing
  launched with. Node/Deno/Workers get flipped to ✅ as each is actually
  exercised (mirrors how x-wing's row for those three flipped same-day in
  the hybrid sprint); Hermes/RN follow issue #45's exact precedent — stay
  ⏳ with a dated note of what's missing, closed by an on-device run, never
  inferred from the ml-kem-768/x-wing rows above them.

## 5. Day-sized sprint split

- **Day 1 — Format + core primitive.** Lock `docs/serialization-format.md`
  §9 first (spec before impl, per the Day-2 hybrid-sprint habit). Implement
  `encryptStream`/`decryptStream` for `ml-kem-768` only. Golden vectors +
  generator script. Cross-check a handful of nonce values against age's
  published test vectors as an extra correctness sanity check (not an
  interop goal — just confirms the `BE88(i) ‖ flag` arithmetic matches a
  known-good reference independent of our own tests).
- **Day 2 — Mutation-check suite, both KEMs.** Add `x-wing` streaming.
  Write every case in §4's mutation list against both algorithms before any
  public export — this is the non-negotiable, so it gets a dedicated day
  before the API surface commitment, same discipline as the hybrid sprint's
  KAT-first Day 1.
- **Day 3 — Public API + runtime verification.** Export
  `encryptStream`/`decryptStream` and the Web Streams adapters. Extend the
  Node/Deno/Cloudflare Workers examples with a streaming roundtrip (large
  synthetic file). Flip `docs/compatibility.md` rows to ✅ for the three
  runtimes actually run; add Hermes/RN rows as ⏳.
- **Day 4 — CLI + docs + bench.** Replace the 1 GiB guard with the
  threshold design in §3. Update CLI tests (large-file roundtrip, guard
  removal, algorithm selection carries over). New streaming-throughput
  benchmark (bench-baseline workflow_dispatch per `.claude/rules/dev-workflow.md`,
  since this changes the benchmark set). Docs: README, a new streaming guide
  alongside `apps/docs/guide/hybrid-encryption.md`, changeset (additive →
  minor, 0.6.0). If Hermes/RN hardware is available, attempt on-device
  validation same-day; otherwise open a tracking issue immediately, same
  pattern as issue #45, rather than leaving it implicit.

## Open questions for approval

1. 64 KiB default chunk size (age's default) — acceptable, or a different
   default preferred?
2. Version-byte choice (`0x03` ml-kem-768-stream, `0x04` x-wing-stream,
   reusing existing header ids) vs. an alternative encoding — any objection?
3. 8 MiB CLI one-shot/streaming cutover and 1 TiB operational ceiling —
   right numbers, or should either move?
4. Any objection to the chunk-size-in-header design (§2) as the one
   deliberate deviation from copying age verbatim?
