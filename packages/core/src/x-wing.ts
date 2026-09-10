/**
 * X-Wing (draft-connolly-cfrg-xwing-kem-10) built from the vendored, FIPS-corrected
 * ML-KEM-768 rather than `@noble/post-quantum`'s own `ml_kem768_x25519` preset.
 *
 * `@noble/post-quantum/hybrid.js` builds that preset by calling its own internal,
 * unpatched `ml_kem768` (`hybrid.ts` imports it from `./ml-kem.ts`, not from anywhere
 * patchable). That means X-Wing's embedded ML-KEM-768 — the component `pqc.keys.generate()`
 * uses by default — still runs the floating-point `Compress_d` (F203-19) and the
 * branch-based implicit-reject/zeroization selection (F203-18) that
 * `vendor/ml-kem/ml-kem.ts` closed for the standalone `ml-kem-768` algorithm entry. See
 * docs/compliance/FIPS-203-MATRIX.md §3.2 for why that row's CONFORMING status does not
 * extend to this composite.
 *
 * The fix is not to vendor X-Wing's combiner: `combineKEMS`, `expandSeedXof` and
 * `_ecdhKem` are generic seed-expansion/composition glue with no ML-KEM math inside them,
 * so neither finding applies to them, and they are public exports of
 * `@noble/post-quantum/hybrid.js` (not internal-only). This module reconstructs the
 * package's own `ml_kem768_x25519` construction verbatim — same argument order, same
 * hard-coded domain-separation label — substituting the vendored `ml_kem768` for the
 * npm one. `combineKEMS` only requires its component KEMs to expose
 * `{ lengths, keygen, getPublicKey, encapsulate, decapsulate }`; the vendored and npm
 * `ml_kem768` share that shape exactly (both built by the same `mk()` factory), so the
 * substitution is a drop-in swap of *implementation*, not of *interface*.
 *
 * KNOWN UPGRADE HAZARD: `_ecdhKem`'s leading underscore is Noble's convention for an
 * internal API, and the package's own README says so explicitly: "`_ecdhKem(curve)` is
 * an internal raw-ECDH component adapter, not a standalone IND-CCA-secure KEM." It has no
 * `@internal` marker blocking the import — it's a normal named export with its own JSDoc
 * `@example` importing it from this exact subpath — but the package reserves the right to
 * rename, reshape or remove it in a minor bump without that being treated as a breaking
 * change, because the package does not consider it public API. A `@noble/post-quantum`
 * version bump must re-check that `_ecdhKem`, `expandSeedXof` and `combineKEMS` still
 * exist with this shape before landing; the cross-check test in `x-wing.test.ts` will
 * fail loudly if `hybrid.js`'s own preset ever diverges from this reconstruction, but a
 * removed export fails at the type-check/build step instead.
 *
 * SECOND CORRECTION (F203-11), on top of the ML-KEM substitution above. Substituting the
 * vendored `ml_kem768` fixes F203-19/F203-18 for X-Wing's embedded ML-KEM, but F203-11 (RBG
 * failure surfacing as `INVALID_KEY` instead of `RBG_FAILURE`) is NOT reachable that way:
 * the failing call is not inside either component KEM. `combineKEMS`'s own returned
 * `encapsulate` samples its *top-level* combined randomness with a bare default parameter —
 * `encapsulate(pk, randomness = randomBytes(msgCoder.bytesLen))` in
 * `@noble/post-quantum/hybrid.js` — using that package's plain, unpatched `randomBytes`,
 * with no RBG-failure wrapping. Verified by reproducing it: stubbing
 * `crypto.getRandomValues` to throw and calling this module's own (pre-fix)
 * `ml_kem768_x25519.encapsulate(publicKey)` threw a raw `Error` from exactly that default
 * parameter, at `hybrid.js`'s `encapsulate` — never touching either component KEM. See
 * docs/compliance/FIPS-203-MATRIX.md §3.4 for the full writeup.
 *
 * The fix is the same shape as the ML-KEM substitution: intervene one layer above the gap,
 * in what this module exports, rather than vendor `combineKEMS` to patch its internal
 * default parameter. `ml_kem768_x25519` below always supplies an explicit `randomness`
 * argument to the composed object's `encapsulate` — sampled via the vendored
 * `sampleRandomness` (the exact F203-11 correction, exported from `vendor/ml-kem/ml-kem.ts`
 * for reuse here) when the caller passes none, forwarded unchanged when the caller does
 * (preserving the derandomized/seeded path `xwing-vectors.test.ts`'s KAT vectors rely on).
 * Because the wrapper's own explicit argument is always present, `hybrid.js`'s default
 * parameter — the actual bug — is never evaluated.
 *
 * See `vendor/ml-kem/NOTICE.md` for the ML-KEM vendoring this module builds on.
 */
import { _ecdhKem, combineKEMS, expandSeedXof } from '@noble/post-quantum/hybrid.js';
import type { KEM } from '@noble/post-quantum/utils.js';
import { asciiToBytes, concatBytes } from '@noble/curves/utils.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sha3_256, shake256 } from '@noble/hashes/sha3.js';

import { ml_kem768, sampleRandomness } from './vendor/ml-kem/ml-kem.js';

// Verbatim copy of `@noble/post-quantum/hybrid.js`'s own `x25519kem` and `ml_kem768_x25519`
// construction (see that file, just above and at its `ml_kem768_x25519` export). Argument
// order and the label bytes are spec-critical: `combineKEMS` derives the wire layout
// (pk_M‖pk_X, ct_M‖ct_X — draft §5.4) from the order components are passed in, and the
// label is the draft's own domain-separation constant. Changing either would silently
// break interoperability with existing X-Wing keys and ciphertexts.
const x25519kem = /* @__PURE__ */ _ecdhKem(x25519);

const inner: KEM = /* @__PURE__ */ (() =>
  combineKEMS(
    32,
    32,
    expandSeedXof(shake256),
    (pk: Uint8Array[], ct: Uint8Array[], ss: Uint8Array[]) =>
      sha3_256(concatBytes(ss[0]!, ss[1]!, ct[1]!, pk[1]!, asciiToBytes('\\.//^\\'))),
    ml_kem768,
    x25519kem,
  ))();

/**
 * X25519 + ML-KEM-768 hybrid preset, built from the vendored ML-KEM-768, with `encapsulate`
 * wrapped so an RBG failure during the combined-randomness sampling surfaces as
 * {@link RbgFailureError} — matching the vendored ML-KEM's own encapsulate — instead of a
 * raw host error (F203-11; see the module doc comment above).
 */
export const ml_kem768_x25519: KEM = Object.freeze({
  ...inner,
  encapsulate(publicKey: Uint8Array, randomness?: Uint8Array) {
    const seed = randomness ?? sampleRandomness(inner.lengths.msgRand!);
    return inner.encapsulate(publicKey, seed);
  },
});
