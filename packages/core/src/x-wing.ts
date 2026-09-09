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
 * See `vendor/ml-kem/NOTICE.md` for the ML-KEM vendoring this module builds on.
 */
import { _ecdhKem, combineKEMS, expandSeedXof } from '@noble/post-quantum/hybrid.js';
import type { KEM } from '@noble/post-quantum/utils.js';
import { asciiToBytes, concatBytes } from '@noble/curves/utils.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sha3_256, shake256 } from '@noble/hashes/sha3.js';

import { ml_kem768 } from './vendor/ml-kem/ml-kem.js';

// Verbatim copy of `@noble/post-quantum/hybrid.js`'s own `x25519kem` and `ml_kem768_x25519`
// construction (see that file, just above and at its `ml_kem768_x25519` export). Argument
// order and the label bytes are spec-critical: `combineKEMS` derives the wire layout
// (pk_M‖pk_X, ct_M‖ct_X — draft §5.4) from the order components are passed in, and the
// label is the draft's own domain-separation constant. Changing either would silently
// break interoperability with existing X-Wing keys and ciphertexts.
const x25519kem = /* @__PURE__ */ _ecdhKem(x25519);

/** X25519 + ML-KEM-768 hybrid preset, built from the vendored ML-KEM-768. */
export const ml_kem768_x25519: KEM = /* @__PURE__ */ (() =>
  combineKEMS(
    32,
    32,
    expandSeedXof(shake256),
    (pk: Uint8Array[], ct: Uint8Array[], ss: Uint8Array[]) =>
      sha3_256(concatBytes(ss[0]!, ss[1]!, ct[1]!, pk[1]!, asciiToBytes('\\.//^\\'))),
    ml_kem768,
    x25519kem,
  ))();
