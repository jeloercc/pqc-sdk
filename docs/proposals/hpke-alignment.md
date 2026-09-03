# Proposal: HPKE (RFC 9180) alignment with X-Wing as the KEM

- **Status:** PROPOSED (2026-09-03) — research and feasibility only. No
  implementation, no decision taken.
- **Origin:** external review, September 2026, which called this the strongest
  strategic point: `pqcenc` is a bespoke envelope where a standard exists.
- **Depends on:** `@pqc-sdk/core` 0.8.1.

## 0. The criticism, stated fairly

`pqcenc.v1`/`v2` is a KEM-DEM envelope we specified ourselves
(`docs/serialization-format.md`). It is simple, documented, and tested — but
it is **ours**. Nothing else reads it. A Go or Rust service cannot decrypt a
`pqcenc` blob without someone porting the format, and "we wrote our own
envelope" is a legitimate thing for a reviewer to push back on when
[RFC 9180 (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html) standardises
exactly this shape.

## 1. Research findings (September 2026)

### RFC 9180 accommodates hybrid KEMs by design

HPKE is parameterised over a KEM, a KDF and an AEAD, identified by a
`KEM ID`/`KDF ID`/`AEAD ID` triple. The KEM is an interface
(`GenerateKeyPair`, `Encap`, `Decap`), not a fixed algorithm, so a hybrid KEM
is accommodated **without changing RFC 9180 itself** — it only needs a
registered KEM ID. This directly answers the feasibility question: yes.

### There is now a working-group draft, and it registers a hybrid

[`draft-ietf-hpke-pq`](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
is at **version 05, dated 2026-07-06, expiring 2027-01-07**. Note the
`draft-ietf-` prefix: this is an adopted HPKE **working-group** document, not
an individual submission — a materially stronger signal than when we last
looked at this area during the hybrid sprint.

It registers, among others:

| KEM                 | ID           |
| ------------------- | ------------ |
| ML-KEM-768          | `0x0041`     |
| MLKEM768-P256       | `0x0050`     |
| **MLKEM768-X25519** | **`0x647a`** |
| ML-KEM-1024         | `0x0042`     |

`MLKEM768-X25519` is the same algorithm pairing this SDK already ships as
`x-wing`: X25519 + ML-KEM-768, 32-byte shared secret.

### The one thing I could **not** confirm, and it is the load-bearing one

Whether `MLKEM768-X25519` (`0x647a`) uses **the X-Wing combiner verbatim**, or
a different combiner over the same two primitives.

Secondary sources state the equivalence — Go's `crypto/hpke` reportedly
documents `MLKEM768X25519` as "also known as X-Wing" — but reading
`draft-ietf-hpke-pq-05` itself, the combiner is **not specified inline**. The
draft defers to referenced documents for the concrete hybrid construction and
says only that the hybrid KEMs "satisfy the KEM interface" with
`Nsecret = Nss`. I could not extract combiner text from the draft.

Per `.claude/rules/crypto-review.md` — _"Spec citations must be verified
against the actual draft text before committing them"_ — **this is recorded as
unverified, not asserted.** It is the first thing to settle, because the whole
proposal branches on it:

- **If identical to X-Wing**: our existing `x-wing` keys are HPKE keys. The
  work is an envelope layer, not a crypto change, and existing key material
  keeps working.
- **If a different combiner**: HPKE support means a _third_ KEM in the SDK,
  new key types, new test vectors, and no reuse of existing `x-wing` keys.
  Considerably more work, and a harder story for users.

**Action before any implementation decision:** read
`draft-ietf-hpke-pq-05` §"PQ/T Hybrid KEMs" and its `[CONCRETE]`/`[GENERIC]`
references end to end, and diff the combiner against
[`draft-connolly-cfrg-xwing-kem-10`](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)
§"Combiner". Cross-check against a shipped implementation's test vectors — Go
stdlib is the best candidate.

### Interop with Go and Rust looks realistic

- **Go**: `crypto/hpke` is in the standard library and reportedly includes
  `MLKEM768X25519` from `draft-ietf-hpke-pq`. A Go stdlib implementation is
  the strongest possible interop target — no third-party dependency for the
  peer.
- **Rust**: the [`hpke`](https://lib.rs/crates/hpke) crate implements RFC 9180
  and, per its description, the pure-PQ KEMs from `draft-ietf-hpke-pq-04` plus
  hybrids from `draft-connolly-cfrg-xwing-kem-10`. That it cites _both_ drafts
  separately is weak evidence they may be distinct constructions — another
  reason to settle the question above.

So "encrypt in TypeScript, decrypt in Go" is plausibly a matter of matching a
KEM/KDF/AEAD triple, not of porting our format. That is the actual prize here.

### What interop would really require of us

1. The KEM ID question resolved (above).
2. HPKE's `KeySchedule` — `LabeledExtract`/`LabeledExpand` over HKDF, with the
   `"HPKE-v1"` label prefix and suite ID. Exact, unforgiving, and well
   specified; RFC 9180 has test vectors, which we would run the way we run
   ACVP vectors today.
3. A decision on **mode**: `mode_base` covers our use case
   (`encrypt`-to-a-public-key). `mode_auth`/`mode_psk` are out of scope for a
   first pass.
4. AEAD alignment: HPKE's `AES-256-GCM` is `AEAD ID 0x0002`. We already use
   AES-256-GCM, so this is a match.
5. Nonce handling changes: HPKE derives per-message nonces from a
   base nonce XOR a sequence number, rather than carrying a random nonce as
   `pqcenc` does. This is a genuine format difference, not a cosmetic one.

## 2. Can it coexist with `pqcenc` v1/v2?

**Yes, and it must.** This is the part I am most confident about.

The envelope already self-describes via a leading version byte, and `decrypt`
dispatches on it (`0x01` v1, `0x02` v2, `0x03`/`0x04` streaming). An HPKE
envelope would take a **new version byte** — say `0x05` — and slot into the
same dispatch. Consequences:

- Every existing `pqcenc` artifact stays valid and decryptable. No migration
  is forced on anyone.
- No golden vectors are regenerated; new ones are added.
- It is **additive** ⇒ minor bump, not major.
- Users choose per call site: `pqcenc` for internal, self-contained use;
  HPKE when a non-JS peer has to read it.

The version-byte scheme's known cost applies (§2 of the streaming proposal:
each new construction consumes version bytes), but one byte for HPKE is
affordable.

## 3. Sketch of what shipping this looks like

Not a plan — a size estimate for the decision.

1. **Verify the combiner question.** Blocking; nothing else starts.
2. **RFC 9180 key schedule + `mode_base`**, validated against the RFC's own
   test vectors before any envelope work. This is where the risk is: it is
   fiddly, exact, and the vectors are the tripwire.
3. **`pqcenc.v5` HPKE envelope** in `docs/serialization-format.md`, spec
   first, per the Day-1 habit.
4. **Cross-language interop test in CI** — the only claim that matters. A
   fixture encrypted by Go's `crypto/hpke` that we decrypt, and vice versa,
   committed as vectors. Per the honest-compatibility rule, "interoperable
   with Go" gets asserted only after that actually runs.
5. Docs: when to choose HPKE over `pqcenc`, and the fact that HPKE here tracks
   a **draft**, so its KEM ID could still change before RFC.

## 4. Recommendation

**Worth doing, but not next, and not blind.**

The strategic argument is right: an SDK whose ciphertexts only its own
implementation can read has a ceiling, and HPKE is the standard that removes
it. The working-group status of `draft-ietf-hpke-pq` and a Go **stdlib**
implementation make this materially more attractive than at the last look.

But `draft-ietf-hpke-pq` is a draft that **expires 2027-01-07**, its KEM IDs
are not final, and the combiner question is unresolved. Shipping an envelope
against a moving draft risks a `pqcenc.v5` that needs a `v6` when the draft
changes — the version-byte cost the streaming proposal already flagged.

Proposed sequencing:

1. **Now (cheap, high value):** resolve the combiner question and write down
   the answer. It is a few hours of primary-source reading and decides
   everything downstream.
2. **Then:** if X-Wing ≡ `0x647a`, implement RFC 9180 `mode_base` against the
   RFC's test vectors, with no envelope work — a pure, well-tested primitive
   sitting unused behind the scenes.
3. **When the draft stabilises** (WGLC or IESG processing): add the envelope
   version and the cross-language interop vectors.

## 5. Open questions for review

1. Is cross-language interop an actual requirement from a real user, or
   anticipated? That changes the priority sharply.
2. If HPKE lands, does `pqcenc` become legacy, or stay the default for
   JS-to-JS? My instinct is the latter — HPKE's per-message nonce/sequence
   model is a worse fit for our one-shot API — but it deserves a decision.
3. Do we want HPKE's full `info`/`aad` split, which overlaps with
   `docs/proposals/user-supplied-aad.md`? If HPKE is likely, that proposal's
   API should probably match HPKE's two-channel shape from the start.
4. Is tracking a pre-RFC draft acceptable at all, given
   `.claude/rules/crypto-review.md`'s insistence on established,
   fully-specified constructions? X-Wing set the precedent (we ship a CFRG
   draft), but a draft **KEM ID registry** is more volatile than a draft
   combiner.

## Sources

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [draft-ietf-hpke-pq: Post-Quantum and PQ/T Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/) (v05, 2026-07-06, expires 2027-01-07)
- [draft-ietf-hpke-pq-05 full text](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)
- [draft-connolly-cfrg-xwing-kem-10: X-Wing](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)
- [Go `crypto/hpke`](https://pkg.go.dev/crypto/hpke) — page returned HTTP 500 when fetched on 2026-09-03; the `MLKEM768X25519` / X-Wing equivalence attributed to it here comes from secondary sources and **must be confirmed against the package source**.
- [Rust `hpke` crate](https://lib.rs/crates/hpke)
- [draft-reddy-cose-jose-pqc-hybrid-hpke](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/07/) — related JOSE/COSE binding, not required here but relevant if JWT/COSE interop is ever wanted
