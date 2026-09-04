# Proposal: HPKE (RFC 9180) alignment with X-Wing as the KEM

- **Status:** PROPOSED (2026-09-03) — research and feasibility only. No
  implementation, no decision taken.
- **Blocking question: ANSWERED (2026-09-03).** KEM ID `0x647a`
  (`MLKEM768-X25519`) is the X-Wing combiner verbatim — see
  [§1](#the-load-bearing-question--answered-2026-09-03-it-is-x-wing-verbatim).
  The gate in the review decisions is therefore cleared on the affirmative
  branch: existing `x-wing` keys are already HPKE keys. Implementation
  remains unstarted and still requires its own decision.
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

### The load-bearing question — ANSWERED 2026-09-03: it is X-Wing, verbatim

**`MLKEM768-X25519` (`0x647a`) uses the X-Wing combiner verbatim.** Same
combiner, same domain-separation label, same seed expansion, same key and
ciphertext encodings. It is not a different construction over the same two
primitives.

Three independent lines of evidence, in the order the review decision asked
for them.

**1. Executed test vectors — the strongest evidence, and the one the review
named.** Go's standard-library HPKE test data
([`src/crypto/hpke/testdata/hpke-pq.json`](https://github.com/golang/go/blob/e3088d6eb8ff0d63edc3452cbed827cb67231182/src/crypto/hpke/testdata/hpke-pq.json),
golang/go @ `e3088d6`) contains two vectors with `kem_id: 25722` (= `0x647a`).
Both were run on 2026-09-03 through **this SDK's own X-Wing** — the pinned
`@noble/post-quantum` 0.6.1 `XWing` already wired up as the `x-wing` entry in
`packages/core/src/algorithms.ts`, unmodified, with no HPKE code involved:

- `XWing.keygen(skRm).publicKey` reproduces Go's `pkRm` byte-for-byte (1216
  bytes), for both vectors.
- `XWing.decapsulate(enc, skRm)` reproduces Go's HPKE `shared_secret`
  byte-for-byte (32 bytes), for both vectors — vector index 0
  (`kdf_id` 1, `aead_id` 3) and index 1 (`kdf_id` 17, `aead_id` 3).

A stock X-Wing implementation decapsulating a Go stdlib HPKE encapsulation to
the identical shared secret is the affirmative settlement the review asked
for. It also confirms a second thing worth writing down: for this KEM the
HPKE shared secret **is** the raw KEM output, with no `ExtractAndExpand`
layered on top (`Nsecret = Nss = 32`).

**2. Go standard-library source.** In
[`src/crypto/hpke/pq.go`](https://github.com/golang/go/blob/b130dab7927741223d40f221e27f3bd351e9cddf/src/crypto/hpke/pq.go)
(golang/go @ `b130dab`), `mlkem768X25519` is declared with `id: 0x647a` and
`label: "\./" + "/^\"`, and the shared secret is computed as

```go
func (kem *hybridKEM) sharedSecret(ssPQ, ssT, ctT, ekT []byte) []byte {
	h := sha3.New256()
	h.Write(ssPQ); h.Write(ssT); h.Write(ctT); h.Write(ekT)
	h.Write([]byte(kem.label))
	return h.Sum(nil)
}
```

which is `draft-connolly-cfrg-xwing-kem-10` §5.3 exactly:
`SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`, label last, with
`XWingLabel = 5c2e2f2f5e5c`. The surrounding code matches the rest of the
draft too: `NewPrivateKey` expands a 32-byte seed with SHAKE-256 into a
64-byte ML-KEM seed followed by a 32-byte X25519 scalar (§5.2
`expandDecapsulationKey`); the public key is `pk_M ‖ pk_X` and the
encapsulation is `ct_M ‖ ct_X` (§5.4). Go's own doc comment reads
"MLKEM768-X25519 (a.k.a. X-Wing)" — the secondary claim in the previous
revision of this document was right, and is now confirmed from the source.

**3. Primary spec text.** `draft-ietf-hpke-pq-05` does not inline the
combiner — that reading was correct — because §4 delegates it: the hybrid
KEMs are `[CONCRETE]`'s, and "the GenerateKeyPair, Encap, and Decap
algorithms are identical". `[CONCRETE]` is
[`draft-irtf-cfrg-concrete-hybrid-kems-03`](https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.txt),
whose §4.2 (`MLKEM768-X25519`) says in as many words:

> This hybrid KEM combines ML-KEM-768 with X25519 using the CG framework from
> \[HYBRID-KEMS\]. **It is identical to the X-Wing construction from
> \[XWING-SPEC\]**. […] PRG: SHAKE-256 […] KDF: SHA3-256 […] Label: `\.//^\`
> (hex: 5C2E2F2F5E5C)

with `[XWING-SPEC]` cited as `draft-connolly-cfrg-xwing-kem-10` — the exact
draft this SDK ships against — and constants `Nseed 32 / Nek 1216 /
Ndk 32 / Nct 1120 / Nss 32`, matching our `x-wing` spec entry field for
field. The same statement appears in §4's summary list.

The codepoint history corroborates it: `0x647a` is X-Wing's _own_ requested
value (`draft-connolly-cfrg-xwing-kem-10` §7: "25722 = 25519 + 203"), and
`draft-ietf-hpke-pq-05` §8.2 asks IANA to **replace** that existing entry
rather than allocate a new one. The Rust crate citing both drafts separately
— flagged below as weak evidence they might differ — is now explained: it
cites both because the hybrid _is_ X-Wing.

**Where it is genuinely not identical: `DeriveKeyPair`, and nothing else.**
X-Wing §5.6 derives the 32-byte seed as plain `SHAKE256(ikm, 32)`, while
`draft-ietf-hpke-pq-05` §4 uses HPKE's labeled form,
`SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)` with suite ID
`"KEM" ‖ 0x647a` (this is what Go implements). This is a difference in how a
seed is derived _from an ikm_, not in the KEM: `GenerateKeyPair`, `Encap` and
`Decap` are unchanged, and any 32-byte X-Wing decapsulation key is a valid
HPKE private key for `0x647a` under either. **We are unaffected** — this SDK
generates a random 32-byte seed and never derives one from an ikm.

**What this implies.** The affirmative branch of the review decision holds:

- Existing `x-wing` keys **are** HPKE `0x647a` keys. `SerializePublicKey` /
  `SerializePrivateKey` are the identity, so our 1216-byte public key and
  32-byte secret key need no conversion, no new key type, and no migration.
- HPKE support is an **envelope and key-schedule layer**, not a crypto
  change. No third KEM, no new KAT set for the KEM itself, no reuse problem.
- The remaining work is exactly items 2–5 of §1's "What interop would really
  require of us" — RFC 9180's `KeySchedule`, `mode_base`, AEAD alignment
  (already a match) and the per-message nonce model. The risk sits in the key
  schedule, not in the KEM.

**Reproducing this.** Fetch the two `kem_id: 25722` entries from the Go
testdata file above and feed `skRm` / `enc` to `KEM_ALGORITHMS['x-wing'].kem`.
The check needs no network and no Go toolchain, and is a good candidate for a
committed interop KAT when HPKE work actually starts — deliberately not added
here, since this pass is research only.

### Interop with Go and Rust looks realistic

- **Go**: `crypto/hpke` is in the standard library and reportedly includes
  `MLKEM768X25519` from `draft-ietf-hpke-pq`. A Go stdlib implementation is
  the strongest possible interop target — no third-party dependency for the
  peer.
- **Rust**: the [`hpke`](https://lib.rs/crates/hpke) crate implements RFC 9180
  and, per its description, the pure-PQ KEMs from `draft-ietf-hpke-pq-04` plus
  hybrids from `draft-connolly-cfrg-xwing-kem-10`. It cites _both_ drafts
  because the hybrid is X-Wing; this is no longer evidence of a discrepancy
  (see above).

So "encrypt in TypeScript, decrypt in Go" is plausibly a matter of matching a
KEM/KDF/AEAD triple, not of porting our format. That is the actual prize here.

### What interop would really require of us

1. ~~The KEM ID question resolved~~ — done (above); no KEM work needed.
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

1. ~~**Verify the combiner question.**~~ **Done (2026-09-03): it is X-Wing.**
   No KEM implementation, no new key type, no key migration.
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

The combiner question is now settled affirmatively, which removes the largest
unknown: this is an envelope layer over KEM code we already ship and test.
What remains is that `draft-ietf-hpke-pq` is a draft that **expires
2027-01-07** and its KEM IDs are not final. Shipping an envelope against a
moving draft risks a `pqcenc.v5` that needs a `v6` when the draft changes —
the version-byte cost the streaming proposal already flagged. Note the
codepoint is the more stable half of that risk: `0x647a` is X-Wing's own
long-standing requested value, not a fresh allocation.

Proposed sequencing:

1. ~~**Now:** resolve the combiner question and write down the answer.~~
   **Done 2026-09-03** — X-Wing ≡ `0x647a`, recorded in §1.
2. **Next (not started, still needs a go/no-go):** implement RFC 9180
   `mode_base` and the key schedule against the RFC's test vectors, with no
   envelope work — a pure, well-tested primitive sitting unused behind the
   scenes. The KEM half is already done and shipping.
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
- Go `crypto/hpke` source — [`src/crypto/hpke/pq.go`](https://github.com/golang/go/blob/b130dab7927741223d40f221e27f3bd351e9cddf/src/crypto/hpke/pq.go) (golang/go @ `b130dab`) and [`src/crypto/hpke/testdata/hpke-pq.json`](https://github.com/golang/go/blob/e3088d6eb8ff0d63edc3452cbed827cb67231182/src/crypto/hpke/testdata/hpke-pq.json) (@ `e3088d6`), both read on 2026-09-03. The `MLKEM768X25519` / X-Wing equivalence is now **confirmed against this source and its vectors**, not attributed to secondary sources. (`pkg.go.dev/crypto/hpke` still returned HTTP 500; the GitHub source was used instead, as the review decision directed.)
- [`draft-irtf-cfrg-concrete-hybrid-kems-03`](https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.txt) — the `[CONCRETE]` reference of `draft-ietf-hpke-pq-05`; §4.2 is where `MLKEM768-X25519` is defined as identical to X-Wing
- [Rust `hpke` crate](https://lib.rs/crates/hpke)
- [draft-reddy-cose-jose-pqc-hybrid-hpke](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/07/) — related JOSE/COSE binding, not required here but relevant if JWT/COSE interop is ever wanted

## Review decisions (2026-09-03)

Approved as a proposal, and placed **first in priority — but gated**. No
implementation work begins until the blocking question below is answered.

1. **Priority: first of the three**, ahead of
   [signcryption](./signcryption.md) and
   [user-supplied AAD](./user-supplied-aad.md). The strategic argument is
   accepted: an SDK whose ciphertexts only its own implementation can read
   has a ceiling, and HPKE is the standard that removes it.
2. **Gated on the combiner question in §1**, which is research, not code.
   Whether KEM ID `0x647a` (`MLKEM768-X25519`) uses the X-Wing combiner
   verbatim decides the cost of everything downstream, and it must be settled
   from **primary text** before anything is built:
   - **If it is X-Wing** — existing `x-wing` keys are already HPKE keys,
     interop is close, and the work is an envelope layer rather than a crypto
     change.
   - **If it is not** — a third KEM in the SDK is a _different project_ and
     should be named as one, not folded into this proposal.
3. **Verification route, in order.** Priority source is the **Go standard
   library `crypto/hpke` source on GitHub**: if it implements
   `MLKEM768X25519`, the combiner is in the code and its test vectors are
   primary evidence. Compare those vectors against
   [`draft-connolly-cfrg-xwing-kem-10`](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)
   Appendix C. **Matching vectors settle it affirmatively; a different
   combiner settles it negatively with equal force.** Secondary paths if that
   fails: the draft's referenced `[CONCRETE]`/`[GENERIC]` documents, then the
   CFRG list archives.

## Gate outcome (2026-09-03)

**The gate is cleared, affirmatively.** KEM ID `0x647a` uses the X-Wing
combiner verbatim; the evidence and exact citations are in
[§1](#the-load-bearing-question--answered-2026-09-03-it-is-x-wing-verbatim).
Recorded here as well because this document is the record.

- **Route used:** the priority route worked. Go's stdlib `crypto/hpke` does
  implement `MLKEM768X25519`, its combiner is in `pq.go`, and its committed
  test vectors were checked against this SDK's own X-Wing. The `[CONCRETE]`
  reference (`draft-irtf-cfrg-concrete-hybrid-kems-03` §4.2) independently
  states the identity in prose. The CFRG archives were not needed.
- **Consequence for decision 2:** the "if it is X-Wing" branch applies.
  Existing `x-wing` keys are already HPKE keys, interop is close, and the
  work is an envelope layer rather than a crypto change. There is no third
  KEM and no separate project to name.
- **Still not decided:** whether to build it, and when. The gate was on the
  research question only. §5's open questions — in particular whether
  cross-language interop is a real user requirement — are untouched by this
  finding and remain the actual go/no-go input.
- **Freshness caveat.** Both drafts are Internet-Drafts and this answer is
  true as of the versions cited (`draft-ietf-hpke-pq-05`,
  `draft-irtf-cfrg-concrete-hybrid-kems-03`,
  `draft-connolly-cfrg-xwing-kem-10`, itself dated March 2026 with a stated
  expiry of 2026-09-03). Re-check the combiner and the `0x647a` assignment
  against the then-current drafts before any implementation lands, per the
  `docs/compatibility.md` precedent about numbers that silently expire.

4. **The answer is recorded in this document**, with the exact citation and
   the date, whichever way it lands — not only in a session report. This
   document is the record. (The bundle-size figure in
   `docs/compatibility.md` is the cautionary precedent: a correctly measured
   number that silently expired because nothing re-checked it.)
