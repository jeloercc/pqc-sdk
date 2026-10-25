# Threat model — `@pqc-sdk/core`

Prepared for an independent security audit. Scope, version and commit are
in [`AUDIT-SCOPE.md`](./AUDIT-SCOPE.md). This document states what the SDK
is meant to protect, against whom, and — as explicitly — what it does not
protect and why. Claims cite the code or the spec they rest on; where a
property depends on the caller or the platform, that is said instead of
implied.

Facts here were checked on 2026-10-25 against commit
`715221290f150171d131e0abd1ed7dc9706dfa3b` (`main`), whose `packages/core`
production source is identical to the audited release (see
`AUDIT-SCOPE.md`).

## 1. What the SDK is

A library, not a protocol. It offers:

- **One-shot hybrid encryption** (`pqc.encrypt` / `pqc.decrypt`): a fresh
  KEM encapsulation to the recipient's public key per message; the KEM
  shared secret is used directly as the AES-256-GCM key; the 2-byte header
  `(envelopeVersion, headerId)` is bound as GCM additional data.
  Envelopes: v1 ML-KEM-768, v2 X-Wing (default), v3 ML-KEM-512,
  v4 ML-KEM-1024 (`docs/serialization-format.md` §2).
- **Streaming encryption** (`encryptStream` / `decryptStream` /
  `collectDecryptStream`): one encapsulation per stream, AES-256-GCM per
  chunk with age's STREAM nonce (`BE88(i) ‖ lastFlag`), 3-byte header as AAD
  (`docs/serialization-format.md` §9).
- **Signatures** (`pqc.sign` / `pqc.verify`): ML-DSA-44/65/87 (FIPS 204),
  hedged signing with fresh 32-byte `rnd` per call, optional context string
  ≤ 255 bytes (`packages/core/src/sign.ts`).
- **Key generation and serialization** (`pqc.keys.*`): `pqcv1.<alg>.<use>.<base64url>`
  tokens with exact length checks (`docs/serialization-format.md` §1).

Primitives come from `@noble/*`. ML-KEM and ML-DSA run from a vendored,
modified copy of `@noble/post-quantum` 0.7.1
(`packages/core/src/vendor/`); X-Wing composes that ML-KEM-768 with X25519
and the `combineKEMS` / `expandSeedXof` / `_ecdhKem` helpers of the
published `@noble/post-quantum` 0.7.1, unmodified (`packages/core/src/x-wing.ts`).

The SDK has no network, storage or key-distribution layer. Transport,
identity, key storage and key rotation belong to the application.

## 2. Assets

| ID  | Asset                   | Includes                                                                                                                                                                      | Property wanted                              |
| --- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| A1  | **Secret keys**         | KEM secret keys (ML-KEM decapsulation keys; the 32-byte X-Wing seed), ML-DSA secret keys, their serialized `pqcv1.*.secret.*` tokens                                          | Confidentiality                              |
| A2  | **Plaintext**           | Data passed to `encrypt` / `encryptStream`; output of `decrypt` / `decryptStream`. Derived secrets: the per-message KEM shared secret (= AES-256 key) and per-signature `rnd` | Confidentiality, integrity                   |
| A3  | **Signature integrity** | That a signature verifying under public key `pk` was produced by the holder of the matching secret key, over exactly that message (and context)                               | Unforgeability (EUF-CMA as FIPS 204 targets) |

Not assets of the SDK: metadata (who talks to whom, when, message sizes),
public keys (public by design, but their **authenticity** matters — see §3.1),
availability.

## 3. Adversaries

Each subsection: capabilities → what the SDK protects → what it does not,
and why.

### 3.1 Network attacker

Observes, drops, reorders, replays and modifies traffic between parties,
and can inject messages.

**Protects**

- **A2 confidentiality and integrity in transit.** Ciphertexts are
  AEAD-sealed; any modification of header, KEM ciphertext, nonce or sealed
  payload fails closed with `PqcError` (`DECRYPTION_FAILED`, or
  `INVALID_CIPHERTEXT` for an unknown/mismatched header before any crypto).
  Guarded by `properties.test.ts`, `key-mutations.test.ts`,
  `stream-mutations.test.ts`, `deserialize-fuzz.test.ts`.
- **No algorithm downgrade inside the SDK.** There is no negotiation: the
  envelope is chosen by the recipient's key, and decryption rejects an
  envelope whose `(version, headerId)` does not match the decrypting key
  (`encrypt.ts`, `docs/serialization-format.md` §6).
- **Stream reordering, truncation and extension** are detected: the chunk
  index and last-chunk flag are in the nonce; a stream may end only after a
  chunk authenticated as final; trailing bytes are rejected (§9.3).
- **A3**: a modified message or signature makes `verify` return `false`.

**Does not protect**

- **Sender authentication of encryption.** Anyone holding the recipient's
  public key can produce a valid ciphertext; `decrypt` succeeding says
  nothing about who encrypted. Authenticity requires `sign`, and the SDK
  offers no combined sign-and-encrypt construction — composing them
  (what is signed, what is encrypted, binding recipient identity) is the
  application's responsibility.
- **Public-key authenticity.** An attacker who substitutes the recipient's
  public key during distribution reads everything encrypted to it. The SDK
  has no PKI, certificates or key pinning.
- **Replay.** A recorded valid ciphertext or signed message is still valid
  when replayed; there are no timestamps, counters or session state.
- **Metadata.** Ciphertext length is plaintext length plus a fixed overhead
  per algorithm; the header reveals the algorithm; timing is visible.
- **Transport security.** The SDK does not replace TLS.

### 3.2 Attacker with access to ciphertexts

Holds ciphertexts (passively collected or chosen), and may be able to submit
crafted ciphertexts to a party that decrypts them and observe the outcome
(a decryption oracle).

**Protects**

- **IND-CCA2 KEMs.** ML-KEM (FIPS 203, Fujisaki–Okamoto with implicit
  rejection) and X-Wing (draft-connolly-cfrg-xwing-kem-10). The implicit
  rejection uses an arithmetic mask, not a branch — closed finding F203-18,
  regression test `vendor/ml-kem/__tests__/implicit-reject.test.ts`.
- **One error for every authentication failure.** Tampered, truncated or
  wrong-key ciphertexts all produce `DECRYPTION_FAILED`; raw `@noble` errors
  do not leak through (mutation matrices above).
- **Key and nonce uniqueness.** Every `encrypt` call encapsulates afresh, so
  each AES-256 key is used for exactly one message and the random 96-bit
  nonce cannot collide under the same key (`encrypt.ts`, "NONCE SAFETY
  INVARIANT"). Streams use a fresh encapsulation per stream with
  position-derived nonces.

**Does not protect**

- **Timing side channels.** JavaScript gives no constant-time guarantee;
  JIT compilation, garbage collection and engine internals can make timing
  data-dependent. A remote attacker measuring decryption time is not
  defended against beyond what the primitives' constant-time-style code
  achieves in practice. (SECURITY.md, "Threat model: known limits".)
- **Format-level errors are distinguishable from authentication errors, by
  design.** `INVALID_CIPHERTEXT` (unknown/mismatched header, wrong length,
  stream chunk-size exponent out of range) is raised before any
  cryptographic work and is decided by public bytes only;
  `DECRYPTION_FAILED` covers every secret-dependent failure.
- **Incremental release in `decryptStream`.** Each chunk is authenticated
  before it is yielded, but a stream truncated or tampered after chunk `k`
  yields chunks `0..k` before throwing. Callers that cannot roll back must
  use `collectDecryptStream`, which returns nothing unless the whole stream
  authenticates (`stream.ts`, JSDoc "IMPORTANT — incremental release").
- **Plaintext length** (see §3.1).

### 3.3 Future quantum attacker (harvest now, decrypt later)

Records ciphertexts today and later obtains a cryptographically relevant
quantum computer.

**Protects**

- **Default encryption is hybrid.** X-Wing's shared secret stays secure if
  **either** ML-KEM-768 or X25519 holds; a quantum attacker breaks X25519
  but must still break ML-KEM-768 (NIST category 3). Explicit opt-in gives
  pure ML-KEM-512/768/1024 (categories 1/3/5).
- **Symmetric layer.** AES-256-GCM; Grover's algorithm leaves roughly
  128-bit security.
- **Signatures** are ML-DSA (FIPS 204), not classical.

**Does not protect**

- **No forward secrecy.** One-shot and streaming encryption target a
  long-term recipient key. Anyone who later obtains that secret key (A1) —
  by theft, legal compulsion or future cryptanalysis of ML-KEM — decrypts
  every recorded message ever sent to it. There is no ratchet or ephemeral
  key agreement; rotating recipient keys is the application's job.
- **No hybrid signatures.** If ML-DSA were broken, there is no classical
  signature to fall back on.
- **Lower categories by choice.** `ml-kem-512` (category 1) is available on
  explicit opt-in; data with a long confidentiality lifetime should use the
  default or `ml-kem-1024`.
- **Assumption on ML-KEM itself.** HNDL protection rests on ML-KEM's
  security (and, until quantum computers exist, on X25519 as well).

### 3.4 Supply-chain attacker

Tampers with something between the source and the code that runs: an
upstream dependency, the npm registry, the build or release pipeline, or a
maintainer account.

**Protects** (what the project controls)

- **Exact pins for the crypto dependencies of core.**
  `@noble/ciphers 2.2.0`, `@noble/curves 2.4.0`, `@noble/hashes 2.4.0`,
  `@noble/post-quantum 0.7.1` — no caret ranges (`packages/core/package.json`).
- **Vendored ML-KEM / ML-DSA with recorded upstream digests.**
  `vendor-drift-check.yml` reports when a vendored file's recorded pristine
  copy no longer matches upstream at the pinned version, or when upstream
  releases (detect-and-notify; re-vendoring is a manual reviewed process,
  `vendor/ml-kem/NOTICE.md`).
- **Known-answer and interop tests catch a functionally altered
  primitive**: NIST ACVP vectors, X-Wing draft-10 vectors, CIRCL (Go)
  cross-checks, golden wire-format vectors — run in CI with
  `pnpm install --frozen-lockfile`.
- **Release pipeline.** Packages are published only by
  `.github/workflows/release.yml` via npm trusted publishing (OIDC); the
  repository holds **no** Actions secrets (checked with `gh secret list`),
  so there is no long-lived npm token to steal. Every published version of
  all four packages carries an npm SLSA provenance attestation naming
  `jeloercc/pqc-sdk` and `release.yml` (verifiable with
  `npm audit signatures`).
- **Added for this audit:** a CycloneDX SBOM per published package
  attached to each GitHub release; every GitHub Action in every workflow,
  GitHub-owned and third-party, pinned by full commit SHA; OpenSSF
  Scorecard published weekly.

**Does not protect**

- **A malicious version of a pinned dependency stays pinned.** Exact pins
  stop silent upgrades, not a compromised release that was pinned
  deliberately; review of bumps is the control.
- **Transitive ranges float.** Core's own pins do not constrain what its
  dependencies declare (e.g. `@noble/post-quantum 0.7.1` brings its own
  `@noble/ciphers 2.4.0`), and `@pqc-sdk/cli`, `@pqc-sdk/mcp-server` and
  `@pqc-sdk/langchain` depend on caret ranges resolved at the consumer's
  install time (`@pqc-sdk/mcp-server 0.4.1` resolves to ~100 packages).
  Consumers without a lockfile get whatever resolves that day.
- **Repository and account compromise.** `main` currently has **no branch
  protection and no rulesets**, and the project has a single maintainer.
  Anyone with write access to the repository (or the maintainer's GitHub
  account) can push to `main`, which runs `release.yml` with
  `id-token: write` and can publish with provenance. Provenance proves
  where a package was built, not that the change was reviewed.
- **GitHub's runner infrastructure is trusted.** SHA pins fix which action
  code runs, not the security of the hosted runners or of the actions'
  own dependencies, and pins only move when someone updates them.
- **The application's own environment** (its other dependencies, build
  tools, bundler) is outside the SDK's reach — see assumption S2.

### 3.5 Local attacker with access to process memory

Can read the process's memory: a debugger, heap snapshots, core dumps,
swap, a co-resident process with sufficient privileges, or a malicious
dependency in the same JavaScript realm.

**Protects** (best effort only)

- **Partial zeroization.** The vendored ML-KEM and ML-DSA code wipes its
  internal intermediates with `cleanBytes` — 39 call sites in
  `packages/core/src/vendor/` (the recount command is in SECURITY.md,
  "Threat model: known limits"). This covers both implicit-rejection
  candidates in ML-KEM decapsulation (F203-18) and the ML-DSA verify path
  (F204-10). Outside the vendored code, the only wipe is the per-signature
  `rnd` in `sign.ts` (`rnd.fill(0)` in a `finally`).

**Does not protect — and cannot, in JavaScript**

- **Secret keys, shared secrets and plaintext are not wiped.** They are
  returned to the caller or held by the envelope layer. JavaScript has no
  reliable zeroization primitive: a moving garbage collector can relocate a
  `Uint8Array` and leave copies that a later `fill(0)` never reaches.
- **Serialized keys are strings.** `pqc.keys.serialize` returns secret keys
  as immutable strings, which cannot be wiped at all.
- **Same-realm code is fully trusted.** Any script in the same realm can
  read keys from memory, replace globals (`crypto.getRandomValues`,
  `Uint8Array`), or wrap SDK functions.
- **Local side channels** (cache timing, power, speculative execution) are
  outside the threat model (SECURITY.md).
- **Keys at rest** are the application's responsibility. (The CLI and the
  MCP server write key files with restrictive permissions; both packages
  are outside this audit's scope.)

## 4. Assumptions

| ID  | Assumption                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | If it fails                                                                       |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| S1  | **The platform RNG is cryptographically secure.** All randomness comes from `crypto.getRandomValues` (via `@noble/*` `randomBytes`). If it fails, the operation throws; it never continues with weaker randomness. Key generation, encapsulation and signing report that as `PqcError('RBG_FAILURE')`; the one-shot AES-GCM nonce (`encrypt.ts`, `randomBytes(NONCE_LENGTH)`) calls `@noble` directly, so a failure at that step surfaces as the host's raw error instead — noted for the audit. Whether the generator is SP 800-90 approved is the deployment's question (SECURITY.md, "Randomness source"; F203-12). | Key generation, encapsulation, nonces and hedged signing all lose their security. |
| S2  | **The JavaScript environment is not compromised**: no malicious code in the same realm, no tampered globals or prototypes, the installed `@pqc-sdk/*` and `@noble/*` code is what was published.                                                                                                                                                                                                                                                                                                                                                                                                                       | Every property in this document can be bypassed.                                  |
| S3  | **The `@noble/*` primitives are correct as published** (AES-GCM, X25519, SHA-3/SHAKE, the helpers X-Wing uses), and the vendored ML-KEM/ML-DSA corrections are correct. Evidence: NIST ACVP and X-Wing vectors, CIRCL cross-checks; `@noble/post-quantum` has no independent audit yet.                                                                                                                                                                                                                                                                                                                                | Primitive-level breaks propagate to every API.                                    |
| S4  | **The application authenticates public keys** before encrypting to them or verifying with them.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Key substitution (§3.1).                                                          |
| S5  | **The application handles errors fail-closed** and uses `collectDecryptStream` when it cannot act safely on a partially released stream.                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Acting on unauthenticated or partial data.                                        |
| S6  | **The `examples/hermes-standalone` `Math.random` shim is never used outside that example.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | No randomness security at all (SECURITY.md).                                      |

## 5. Out of scope for this model

The CLI, the MCP server and the LangChain tools have their own threats
(key files on disk, model-context leakage — see GHSA-p2f3-84pf-p4jv and the
MCP keystore policy in CLAUDE.md); they are outside the audit scope in
`AUDIT-SCOPE.md`. Availability and denial of service (e.g. very large
inputs) are not modeled.
