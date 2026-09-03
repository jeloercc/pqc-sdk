# Proposal: a signcryption helper (authenticated, correctly bound)

- **Status:** PROPOSED (2026-09-03) — no implementation, no decision taken.
- **Origin:** external review, September 2026: the SDK offers `encrypt` and
  `sign` separately and gives no guidance on combining them, which is a trap.
- **Depends on:** `@pqc-sdk/core` 0.8.1 (`pqc.encrypt`/`decrypt` with
  ML-KEM-768 or X-Wing; `pqc.sign`/`verify` with ML-DSA-65).

## 0. The problem

`pqc.encrypt` gives confidentiality. `pqc.sign` gives authenticity. A user who
wants both will compose them, and the obvious composition is wrong.

**Naive sign-then-encrypt is vulnerable to surreptitious forwarding.** Alice
signs a message and encrypts it to Bob. Bob decrypts, keeps Alice's still-valid
signature over the plaintext, and re-encrypts it to Charlie. Charlie verifies
Alice's signature successfully and concludes **Alice wrote to him** — she never
did. Nothing is broken cryptographically; the signature simply never said who
the message was for.

This is not a hypothetical. It is the flaw
[Don Davis documented in 2001](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html)
across S/MIME, PKCS#7, MOSS, PEM, PGP and XML — every major secure-messaging
format of its day had it. It is a _composition_ bug, which is exactly the kind
an SDK should absorb rather than leave to each caller to rediscover.

Today this SDK is silent on the subject. That silence is the finding.

## 1. Constraint: no homemade composition

`.claude/rules/crypto-review.md` forbids designing secret-mixing and requires
established, fully-specified constructions used verbatim. That rules out
inventing a signcryption scheme. It also, in my reading, rules out adopting an
academic single-primitive signcryption scheme (Zheng-style, NTRU-based, or the
code-based constructions in the literature): they are published and analysed,
but none is standardised, none has NIST vectors, and none has an
implementation in `@noble` we could call rather than write. Writing one is
precisely what the rule exists to prevent.

**Therefore: this should not be a new primitive. It should be the correct
composition of the two primitives we already have** — which is a documented,
prescribed repair, not an invention.

## 2. Proposed construction: sign-the-recipient, then encrypt

Davis prescribes five independent repairs. Recommendation is **his first**,
because it is the smallest change that fixes the actual attack and needs no
new format layer:

> **Sign the recipient's name.** Include the intended recipient's identifier
> in the plaintext _before_ signing, then encrypt: `{{Bob, msg}_a}_B`

Concretely:

1. Caller supplies a **recipient identifier** and the sender's signing key.
2. The SDK builds a canonical, unambiguous binding of
   `(recipientId, message)` — see §3, this is where the care goes.
3. `pqc.sign` over that binding with ML-DSA-65.
4. `pqc.encrypt` the `(binding, signature)` pair to the recipient's KEM key.
5. `unsigncrypt` decrypts, then verifies the signature **and asserts the
   recipient identifier matches the identity the verifier expected** —
   supplied by the caller, never read from the message and trusted.

Step 5's second half is the whole point. Bob can still re-encrypt to Charlie,
but the signed bytes say `recipient = Bob`, and Charlie's call asserts
`recipient = Charlie`, so verification fails. Forwarding stops being
surreptitious.

### Why not the other repairs

- **Encrypt sender's name / include both names** — complementary, and worth
  including both identifiers rather than only the recipient. Cheap.
- **Sign/Encrypt/Sign** — requires the sender to sign ciphertext, adding a
  second signature (3309 bytes with ML-DSA-65) and a second verification. More
  overhead for a property we do not need here.
- **Encrypt/Sign/Encrypt** — two KEM operations, worst overhead.

S/E/S and E/S/E additionally prove _who encrypted_, which matters for
non-repudiation of the ciphertext. That is a different requirement; if it is
wanted, it should be a deliberate second mode, not the default.

## 3. Where this gets dangerous: the encoding

The construction is only as good as the binding in step 2. Concatenating
`recipientId ‖ message` is **exactly the kind of homemade encoding the rules
warn about**: if `recipientId` is attacker-influenced and variable-length,
`("bob", "hello")` and `("bo", "bhello")` produce identical signed bytes, and
the recipient assertion can be bypassed.

The encoding must be unambiguous, and the safe options are:

- **Length-prefixed fields** — each field preceded by a fixed-width big-endian
  length. Simple, verifiable, no dependency.
- **A domain-separation label** plus length prefixes, following the shape RFC
  9180 uses for `LabeledExtract` (a constant label so these signed bytes can
  never be confused with a signature produced for another purpose).

**A domain-separation prefix is not optional.** Without it, a signature made by
`signcrypt` is a valid signature over bytes that some _other_ part of an
application might also produce and verify. The label must be a fixed constant
(e.g. `"pqc-sdk/signcrypt-v1"`), included in the signed input.

This is the single most review-worthy part of the proposal, and it should be
specified in `docs/serialization-format.md` before any implementation, per the
spec-before-impl habit.

## 4. Proposed API

```ts
const sealed = await pqc.signcrypt(message, {
  recipient: bobPublicKey, // KEM key (ml-kem-768 or x-wing)
  sender: aliceSigningKey, // ML-DSA-65 secret key
  recipientId: 'bob@example.com',
  senderId: 'alice@example.com',
});

const { plaintext, senderId } = await pqc.unsigncrypt(sealed, {
  recipient: bobSecretKey,
  sender: alicePublicKey, // expected signer
  recipientId: 'bob@example.com', // asserted, not read from the message
});
```

Design points:

- `recipientId` is **required on both sides**. Making it optional would make
  the vulnerable mode the easy one — the same mistake the naive composition
  makes. If a caller has no natural identifier, a key fingerprint is a
  reasonable default and the docs should say so.
- `unsigncrypt` returns the verified `senderId` rather than having the caller
  parse it, and **throws** rather than returning a boolean, matching how
  `decrypt` fails closed. A boolean return invites `if (ok)` being forgotten.
- Failure modes are distinct but non-oracular: `DECRYPTION_FAILED` for a
  ciphertext problem, and a single `SIGNATURE_INVALID` covering both a bad
  signature and a recipient-identifier mismatch — collapsing them avoids
  telling an attacker which half failed.

## 5. Testing requirements

Beyond roundtrip, the mutation suite must include the attack this exists to
prevent:

- **Surreptitious forwarding is rejected.** Alice signcrypts to Bob; Bob
  decrypts and re-encrypts the inner signed payload to Charlie; Charlie's
  `unsigncrypt` with `recipientId: 'charlie'` **must fail**. Without this test
  the feature is decorative.
- Wrong expected sender key → fails.
- Recipient-identifier mismatch → fails, with the same error as a bad
  signature.
- Encoding ambiguity: `('bo', 'bhello')` must not verify against
  `('bob', 'hello')` — the length-prefix regression test.
- Domain separation: a signature produced by plain `pqc.sign` over the same
  logical content must not verify as a signcryption, and vice versa.
- Both KEMs, and the full tamper matrix on the resulting envelope.

## 6. Format and version

The sealed output is an envelope carrying `(binding, signature)` as the
plaintext of an ordinary `pqcenc` envelope. It can therefore be **built on the
existing envelope with no new version byte** — the inner structure is opaque
to `encrypt`. That keeps this additive: **minor**, no golden-vector
regeneration.

Alternatively it could take its own version byte for self-description
(so `decrypt` could refuse to hand back a raw signcryption payload). Worth a
review decision; I lean to the simpler option, with the inner encoding
specified in `docs/serialization-format.md`.

## 7. Recommendation

**Worth doing, and cheaper than it looks** — it is a composition helper plus a
carefully specified encoding, not new cryptography. The value is that it
removes a documented, historically widespread footgun that this SDK currently
leaves entirely to the caller.

Sequencing: it does not depend on HPKE or user-supplied AAD, though it
overlaps conceptually with AAD (both are about binding context). If
`docs/proposals/user-supplied-aad.md` lands first, the recipient binding could
plausibly reuse the AAD channel for the _encryption_ half, which would be
tidier — worth deciding before implementing either.

## 8. Open questions for review

1. Is the identifier a free-form string, or should the SDK require a key
   fingerprint (removing the "what do I put here?" question and the
   attacker-influenced-input risk)?
2. Do we want the S/E/S mode as well, for non-repudiation of ciphertext?
3. Should the inner encoding get its own section in
   `docs/serialization-format.md` (I think yes) and its own golden vectors
   (I think yes)?
4. Does `signcrypt` belong on the top-level `pqc` object, or in a
   `pqc.advanced` namespace? It has more ways to be misused than
   `encrypt`/`sign`, and the zero-config promise argues for not putting it on
   the main path.

## Sources

- [Don Davis, _Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML_](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html) — the canonical description of surreptitious forwarding and the five prescribed repairs
- [_SoK: Why Johnny Can't Fix PGP Standardization_](https://arxiv.org/pdf/2008.06913) — surveys sign-then-encrypt forwarding attacks in deployed formats
- [RFC 9180 §5.1 (HPKE `mode_auth`)](https://www.rfc-editor.org/rfc/rfc9180.html) — an alternative route to sender authentication, relevant if `docs/proposals/hpke-alignment.md` is adopted
- Signcryption as a single primitive originates with Zheng (1997); surveyed in the [code-based signcryption literature](https://arxiv.org/pdf/2112.07130). Noted for completeness — **not** proposed here, since no standardised, vetted implementation exists to call.
