# Proposal: user-supplied AAD on `encrypt`/`decrypt`

- **Status:** PROPOSED (2026-09-03) — no implementation, no decision taken.
- **Origin:** external review, September 2026. The SDK binds its own header as
  AAD but exposes no way for a caller to bind application context.
- **Depends on:** `@pqc-sdk/core` 0.8.1 (envelopes `pqcenc.v1`/`v2`,
  `docs/serialization-format.md` §2).

## 0. The problem

`pqc.encrypt` already uses AES-GCM's additional-authenticated-data channel, but
only for its own framing: the 2-byte header for one-shot envelopes
(`packages/core/src/encrypt.ts`), and the 3-byte header for every streaming
chunk (§9.3). Callers cannot add anything.

That leaves a real gap. A ciphertext is authenticated as _some_ ciphertext
produced under _some_ key, but not as **this** ciphertext, for **this**
recipient, in **this** context. Concretely, an attacker who can move
ciphertexts around a system can:

- **Re-target**: take a blob encrypted for recipient A's key and store it in
  recipient B's slot. If B holds the same key (shared service key, escrow,
  group key), it decrypts cleanly and B believes it was addressed to them.
- **Re-file**: swap the ciphertext of `document-1234` with that of
  `document-5678` under the same key. Both decrypt; the application now
  associates the wrong plaintext with the wrong record.
- **Roll back a schema**: keep an old ciphertext whose plaintext follows an
  older, weaker application schema, and replay it after the schema changed.

None of these are breaks of AES-GCM. They are exactly what AAD exists to
prevent, and every one is a _deployment_ mistake the SDK currently gives the
caller no tool to avoid.

## 1. Prior art

- **RFC 9180 (HPKE)** takes `info` at context setup and `aad` per
  `Seal`/`Open`. Two distinct channels: one binds the _context_, one binds the
  _message_.
- **age** deliberately has no user AAD; it is a file-encryption tool with a
  fixed recipient model, so its scope is narrower than ours.
- **Tink** exposes `associatedData` on every `Aead.encrypt`/`decrypt` and
  documents it as "not included in the ciphertext, must be supplied identically
  to decrypt".
- **libsodium** `crypto_aead_*` likewise takes `ad` on both sides, unstored.

The consensus shape is clear: **AAD is supplied by the caller on both sides and
is not carried in the ciphertext.**

## 2. The central design question

> Does the AAD go _in_ the envelope, or stay caller-supplied on both sides?

**Recommendation: caller-supplied on both sides. Do not store it.**

Storing it would be the easier API — `decrypt` would need no extra argument,
and a mismatch could be reported precisely. It is the wrong choice:

1. **It is not confidential.** AAD is authenticated, never encrypted. Writing
   a recipient ID or file ID into the envelope leaks exactly the metadata a
   caller most often wants to bind. A user binding `user-4417@example.com`
   would be publishing it.
2. **It destroys the security property.** If the envelope carries its own AAD,
   an attacker who rewrites both the AAD field and re-derives nothing still
   fails the tag — but the _application_ no longer checks anything: `decrypt`
   would authenticate the ciphertext against whatever context the ciphertext
   itself claims. The whole point is that the _verifier_ asserts the expected
   context independently. Self-describing AAD is a tautology.
3. **It is a format change.** Storing it means a new envelope version, new
   golden vectors, and a major bump. Caller-supplied AAD is
   **byte-for-byte format-compatible**: `pqcenc.v1`/`v2` layouts are unchanged
   and an empty AAD reproduces today's exact bytes.

Point 2 is the decisive one. Point 3 is a pleasant consequence.

## 3. Proposed API

```ts
await pqc.encrypt(plaintext, publicKey, { aad });
await pqc.decrypt(ciphertext, secretKey, { aad });

// Streaming: bound identically on every chunk, alongside the header.
pqc.encryptStream(publicKey, source, { aad, chunkSize });
pqc.decryptStream(secretKey, source, { aad });
```

- `aad?: Uint8Array | string` — a string is UTF-8 encoded, matching how
  `encrypt` already accepts string plaintext.
- Omitted or empty ⇒ **exactly today's behaviour and today's bytes**. This
  keeps the change additive and the golden vectors untouched.
- The SDK's own header stays bound regardless; user AAD is _appended_ to it,
  never replaced. Concretely the AAD passed to GCM becomes
  `header ‖ userAad`, so a caller cannot weaken the existing header binding
  by supplying their own.
- A wrong or missing AAD at decrypt fails with the existing
  `DECRYPTION_FAILED` — indistinguishable from a tampered ciphertext, which
  is correct: revealing _which_ AAD would have worked is an oracle.

### Length

GCM permits enormous AAD; we should not. Proposed cap **64 KiB**, rejected
with `INVALID_INPUT` above it. Rationale: AAD is context, not payload, and an
unbounded field invites callers to put the payload there (unencrypted). The
number is arbitrary and worth a review decision.

## 4. Documentation burden — the part that actually decides success

An AAD API is easy to misuse in ways that fail silently _until_ they matter:

- **Encrypt-only binding.** Passing `aad` to `encrypt` and forgetting it at
  `decrypt` does not fail loudly at write time; it fails later, at read time,
  for everyone. The JSDoc must say plainly: the same AAD must be supplied to
  both, and it is the caller's job to reconstruct it independently — from the
  slot the ciphertext was read from, never from the ciphertext.
- **Binding the wrong thing.** Binding a value derived from the ciphertext, or
  a value the attacker controls, buys nothing. The guidance should name good
  choices (recipient key ID, record primary key, schema version, tenant ID)
  and bad ones (a hash of the ciphertext, a client-supplied header).
- **Changing it later.** An AAD is part of the ciphertext's decryptability
  forever. Rotating a recipient ID that was bound as AAD makes old ciphertexts
  undecryptable. This needs a worked example.

This is the incremental-release caveat problem again, and it should get the
same treatment: prominent JSDoc, a guide section, not a buried parameter note.

## 5. Testing requirements

Per `.claude/rules/crypto-review.md`, the mutation suite must cover:

- Roundtrip with AAD (both KEMs, one-shot and streaming).
- **Wrong AAD at decrypt → `DECRYPTION_FAILED`**, for: a different value, a
  truncated value, an extended value, empty-vs-absent, and a one-byte flip.
- **Encrypt with AAD, decrypt without → fails.** And the reverse.
- Streaming: AAD bound on _every_ chunk, so splicing a chunk from a stream
  encrypted under a different AAD fails — extending the existing cross-stream
  splice case.
- **Empty AAD produces byte-identical output to omitting it** — this is what
  keeps the format claim honest, and it belongs in the golden-vector suite.
- Property test: for arbitrary `(plaintext, aad)`, decrypt succeeds with the
  same AAD and fails for any different one.

## 6. Cost and version

Additive, no layout change ⇒ **minor**. Golden vectors are not regenerated
(and the empty-AAD test above proves they should not be). The work is small in
code and mostly in documentation and tests.

## 7. Open questions for review

1. The 64 KiB cap — right number, or no cap, or smaller?
2. Should `aad` be accepted as `string`, or `Uint8Array` only? A string is
   friendlier but invites locale/normalisation mistakes when the two sides are
   different languages. HPKE interop would argue bytes-only.
3. Should the SDK offer a _structured_ helper (e.g. a canonical encoding of
   `{recipient, resource, schemaVersion}`) rather than raw bytes? It would
   prevent the "two sides disagree on concatenation" class of bug, at the cost
   of inventing an encoding — which cuts against our no-homemade-formats
   instinct.
4. Does this interact with the HPKE proposal
   (`docs/proposals/hpke-alignment.md`)? HPKE's `info`/`aad` split is richer
   than a single field; adopting HPKE later may make this API a subset. Worth
   deciding whether to match HPKE's two-channel shape now.

## Review decisions (2026-09-03)

Approved as proposed, **last in priority** — after
[HPKE](./hpke-alignment.md) and [signcryption](./signcryption.md). Last by
sequencing, not by doubt: the central design question is ratified as
answered.

1. **AAD is caller-supplied on both sides and is never stored in the
   envelope.** Approved as recommended in §2.
2. **The reasoning is ratified in the order the proposal gives it**, and this
   matters for anyone revisiting the decision later: a self-describing AAD is
   a **tautology** — the security property depends on the verifier asserting
   the expected context independently, not on reading it back from the
   ciphertext — and storing it would **publish the very metadata a caller
   wanted to bind**, since AAD is authenticated but never encrypted.
   **Byte-for-byte format compatibility is a bonus, not the justification.**
   A future revisit that weighs only the compatibility argument would be
   re-deciding this on the wrong grounds.
3. The open questions in §7 (length cap, `string` vs `Uint8Array`, a
   structured helper, and whether to match HPKE's two-channel `info`/`aad`
   shape) remain open. Question 4 in particular should be revisited **after**
   the HPKE combiner question is settled, since a likely HPKE adoption would
   argue for matching its shape from the start.
