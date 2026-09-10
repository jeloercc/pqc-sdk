// @ts-nocheck -- see "Type checking" in the header below.
/*
 * VENDORED — do not edit to "improve" it. Keep the diff against upstream minimal.
 *
 * Source package : @noble/post-quantum
 * Version        : 0.7.1 (exact, as pinned in packages/core/package.json)
 * Upstream file  : src/ml-kem.ts
 * Upstream repo  : https://github.com/paulmillr/noble-post-quantum
 * License        : MIT (c) 2024 Paul Miller — full text in ./NOTICE.md
 * Vendored on    : 2026-09-07
 *
 * Why vendored: the published `dist` of @pqc-sdk/core imports @noble/post-quantum as an
 * external runtime import, so consumers execute their own registry copy and a local patch
 * or override cannot reach them. Vendoring the ML-KEM surface into src/ is the only way a
 * FIPS 203 correction actually ships. See docs/compliance/FIPS-203-MATRIX.md.
 *
 * Modifications relative to upstream 0.7.1:
 *   1. Import specifiers './_crystals.ts' and './utils.ts' -> '.js' (this repo's tsconfig
 *      does not enable allowImportingTsExtensions).
 *   2. F203-19: compress(d).encode() re-implemented with BigInt to remove IEEE-754
 *      floating-point division (FIPS 203 §3.3 / §4.2.1). See the comment at that function.
 *   3. F203-11: RBG failure during encapsulation now throws RbgFailureError instead of
 *      propagating an opaque upstream error (FIPS 203 Algorithm 20, steps 2-4).
 *   4. F203-18: both decapsulate() implementations select the shared secret through the
 *      branch-free selectSharedSecret() mask and zeroize both candidates unconditionally,
 *      instead of branching twice on the secret implicit-reject flag (FIPS 203 §6.3).
 *   5. Added the `@ts-nocheck` directive on line 1 — see below.
 *
 * Type checking: this repo compiles with `noUncheckedIndexedAccess: true`, which upstream
 * does not use. Every one of the 37 resulting errors across the three vendored files is
 * `T | undefined` from an array index inside hot lattice arithmetic; none indicates a real
 * defect. The alternatives were to sprinkle non-null assertions through upstream
 * cryptographic code — turning a reviewable diff into an unreviewable one — or to weaken
 * the flag for the whole package. `@ts-nocheck` is the narrower trade: it suppresses
 * checking of this file only, and the explicitly annotated exports (`ml_kem768` et al.)
 * still present correct types to importers. The cost is real and should be stated plainly:
 * the vendored implementation is not type-checked by this repo's gate. It is covered
 * instead by the ACVP known-answer vectors and by ./__tests__/.
 */
/**
 * ML-KEM: Module Lattice-based Key Encapsulation Mechanism from
 * [FIPS-203](https://csrc.nist.gov/pubs/fips/203/ipd). A.k.a. CRYSTALS-Kyber.
 *
 * Key encapsulation is similar to DH / ECDH (think X25519), with important differences:
 * * Unlike in ECDH, we can't verify if it was "Bob" who've sent the shared secret
 * * Unlike ECDH, it is probabalistic and relies on quality of randomness (CSPRNG).
 * * Decapsulation never throws an error, even when shared secret was
 *   encrypted by a different public key. It will just return a different shared secret.
 *
 * There are some concerns with regards to security: see
 * [djb blog](https://blog.cr.yp.to/20231003-countcorrectly.html) and
 * [mailing list](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/W2VOzy0wz_E).
 *
 * Has similar internals to ML-DSA, but their keys and params are different.
 *
 * Check out [official site](https://www.pq-crystals.org/kyber/resources.shtml),
 * [repo](https://github.com/pq-crystals/kyber),
 * [spec](https://datatracker.ietf.org/doc/draft-cfrg-schwabe-kyber/).
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { sha3_256, sha3_512, shake256 } from '@noble/hashes/sha3.js';
import { type CHash, swap32IfBE, u32 } from '@noble/hashes/utils.js';
import { genCrystals, type XOF, XOF128 } from './_crystals.js';
import {
  abytes,
  cleanBytes,
  type Coder,
  copyBytes,
  equalBytes,
  getMask,
  type KEM,
  randomBytes,
  splitCoder,
  type TArg,
  type TRet,
  vecCoder,
} from './utils.js';

/** Key encapsulation mechanism interface */

/**
 * LOCAL ADDITION (F203-11). Signals that the platform random bit generator failed while
 * ML-KEM was sampling its own randomness — it does **not** indicate a bad input.
 *
 * FIPS 203 Algorithm 20 (ML-KEM.Encaps) treats this as a distinct outcome from an input
 * check failure:
 *
 *     1: m <- B^32
 *     2: if m == NULL then
 *     3:     return ⊥      ▷ return an error indication if random bit generation failed
 *     4: end if
 *
 * Upstream let whatever `randomBytes` happened to throw propagate, which the SDK's
 * `encapsulateTo` catch-all then reported as an invalid encapsulation key. Raising a
 * dedicated type lets the caller discriminate on the type rather than on an arbitrary host
 * error message. See docs/compliance/FIPS-203-MATRIX.md §3.4.
 */
export class RbgFailureError extends Error {}

/**
 * LOCAL ADDITION (F203-11). Samples `n` bytes and maps any failure of the underlying RBG to
 * {@link RbgFailureError}. The length check stands in for the standard's `m == NULL` test:
 * a host that returns short or malformed output has equally failed to produce randomness.
 *
 * The thrown message deliberately carries no key material, no shared secret and no host
 * error text — only the fact of failure and the requested length.
 *
 * Exported so `x-wing.ts` can reuse it: `combineKEMS`'s own top-level randomness sampling
 * (its `encapsulate`'s default parameter, in the npm-sourced, unvendored combiner) has this
 * same gap, and it is not reachable by correcting ML-KEM's own `encapsulate`/`decapsulate` —
 * see docs/compliance/FIPS-203-MATRIX.md §3.4 for why X-Wing needs this sampler applied one
 * layer higher, at the composition in `x-wing.ts`, rather than inside this file.
 */
export const sampleRandomness = (n: number): TRet<Uint8Array> => {
  let out: TRet<Uint8Array>;
  try {
    out = randomBytes(n);
  } catch {
    throw new RbgFailureError(`the platform RBG failed to produce ${n} random bytes`);
  }
  if (out == null || out.length !== n) {
    throw new RbgFailureError(`the platform RBG failed to produce ${n} random bytes`);
  }
  return out;
};

/**
 * LOCAL ADDITION (F203-18). Selects between the two shared-secret candidates without a
 * source-level branch on the secret implicit-reject flag.
 *
 * FIPS 203 §6.3, on step 9 of ML-KEM.Decaps_internal: "The 'implicit reject' flag computed
 * in step 9 (by comparing c and c′) is a secret piece of intermediate data. As specified in
 * the requirements in Section 3.3, this flag shall be destroyed prior to
 * ML-KEM.Decaps_internal terminating. In particular, returning the value of the flag as an
 * output in any form is not permitted."
 *
 * Upstream never returned the flag, so the letter of the last sentence was already met. What
 * it did do was branch on it twice — `isValid ? Khat : Kbar` to choose the return value and
 * `!isValid ? Khat : Kbar` to choose which candidate to zeroize. Those are control-flow
 * decisions, and which heap object survives a call is exactly the kind of secret-dependent
 * observable the Fujisaki-Okamoto implicit-reject construction exists to remove.
 *
 * Here `-Number(isValid) & 0xff` yields 0xff for true and 0x00 for false, so every output
 * byte is computed from both inputs and the caller destroys both candidates unconditionally.
 *
 * Honest limit, which must not be overstated anywhere this is cited: this removes the branch
 * from the source, not from the machine. JavaScript exposes no verifiable constant-time
 * primitives, the JIT may still specialise on observed values, and a primitive boolean
 * (`isValid` itself) cannot be zeroized the way a Uint8Array can. That is a property of the
 * language, not a remaining defect in this function.
 */
const selectSharedSecret = (
  isValid: boolean,
  onValid: Uint8Array,
  onReject: Uint8Array
): TRet<Uint8Array> => {
  const mask = -Number(isValid) & 0xff;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (onValid[i] & mask) | (onReject[i] & ~mask & 0xff);
  return out as TRet<Uint8Array>;
};

const N = 256; // Kyber (not FIPS-203) supports different lengths, but all std modes were using 256
const Q = 3329; // 13*(2**8)+1, modulo prime
const F = 3303; // 3303 ≡ 128**(−1) mod q (FIPS-203)
const ROOT_OF_UNITY = 17; // ζ = 17 ∈ Zq is a primitive 256-th root of unity modulo Q. ζ**128 ≡−1
// treeshake: keep genCrystals behind the object so PARAMS-only bundles can drop it entirely.
// Shared CRYSTALS helper in the ML-KEM branch: Kyber mode, 7-bit bit-reversal,
// and Uint16Array polys because current coefficients stay reduced modulo q.
const crystals = /* @__PURE__ */ genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly: (n: number): TRet<Uint16Array> => new Uint16Array(n) as TRet<Uint16Array>,
  brvBits: 7,
  isKyber: true,
});

/** FIPS 203: 7. Parameter Sets */
/** Public ML-KEM parameter-set description. */
export type KEMParam = {
  /** Polynomial size. */
  N: number;
  /** Module rank. */
  K: number;
  /** Prime modulus. */
  Q: number;
  /** CBD parameter used for secret-key noise. */
  ETA1: number;
  /** CBD parameter used for error noise. */
  ETA2: number;
  /** Compression width for the `u` vector. */
  du: number;
  /** Compression width for the `v` polynomial. */
  dv: number;
  /** Required strength of the randomness source in bits. */
  RBGstrength: number;
};
/** Internal params of ML-KEM versions */
// prettier-ignore
/** Built-in ML-KEM parameter presets keyed by the public export names
 * `ml_kem512` / `ml_kem768` / `ml_kem1024`.
 * `RBGstrength` is Table 2's required randomness-source strength in bits,
 * not a generic security label.
 */
export const PARAMS: Record<string, KEMParam> = /* @__PURE__ */ (() =>
  Object.freeze({
    512: Object.freeze({ N, Q, K: 2, ETA1: 3, ETA2: 2, du: 10, dv: 4, RBGstrength: 128 }),
    768: Object.freeze({ N, Q, K: 3, ETA1: 2, ETA2: 2, du: 10, dv: 4, RBGstrength: 192 }),
    1024: Object.freeze({ N, Q, K: 4, ETA1: 2, ETA2: 2, du: 11, dv: 5, RBGstrength: 256 }),
  } as const))();

// FIPS-203: compress/decompress
const compress = (d: number): Coder<number, number> => {
  // d=12 is the ByteEncode12/ByteDecode12 path, not lossy compression.
  // ByteDecode12 interprets each 12-bit word modulo q; without that reduction the public-key
  // modulus check in encapsulate() becomes a no-op for malformed coefficients like 4095.
  if (d >= 12) return { encode: (i: number) => i, decode: (i: number) => (i >= Q ? i - Q : i) };
  // Comments map to python implementation in RFC (draft-cfrg-schwabe-kyber)
  // const round = (i: number) => Math.floor(i + 0.5) | 0;
  const a = 2 ** (d - 1);
  // LOCAL MODIFICATION (F203-19). Upstream 0.7.1 computed `encode` as
  //     ((i << d) + Q / 2) / Q
  // Q is 3329, so `Q / 2` is the non-integer 1664.5 and the outer `/ Q` is a division by a
  // non-power-of-two. In JavaScript `/` is always IEEE-754 double division, so both are
  // floating-point operations. FIPS 203 §3.3 states "Implementations of ML-KEM shall not
  // use floating-point arithmetic", and §4.2.1 repeats it for Compress_d/Decompress_d
  // specifically: "Floating-point computations shall not be used." Both are `shall`
  // (FIPS 203 §2.1), so this is a requirement, not a recommendation.
  //
  // BigInt has no floating-point representation and its `/` truncates toward zero, so the
  // replacement cannot introduce a rounding error. Identity used, for a, b >= 0:
  //     round_half_up(a / b) == floor((2a + b) / 2b)
  // with a = i * 2^d and b = Q.
  //
  // `decode` was already integer-only (`>>> d` is an integer shift) and is left untouched.
  //
  // Equivalence is not assumed: vendor/ml-kem/__tests__/compress-equivalence.test.ts
  // checks all 36,619 (i, d) pairs of the complete domain (i in [0, Q), d in [1, 11])
  // against both the original floating-point expression and the §4.2.1 definition
  // evaluated in exact rational arithmetic. Zero discrepancies is the only passing result.
  //
  // Note on the contract: upstream `encode` returned an unrounded double (e.g. 0.5) and
  // relied on every caller applying `& getMask(d)` to truncate it. This version returns
  // the already-floored integer, so it agrees with upstream *after* masking, not before.
  // That is safe because both call sites mask — `bitsCoder` does `c.encode(...) & mask`
  // in _crystals.ts, and `__tests.Compress_d` below does `& getMask(d)` — and it is a
  // strictly better contract, since the returned value is now a Z_(2^d) member as the
  // standard defines it.
  const twoQ = BigInt(2 * Q);
  const bigQ = BigInt(Q);
  const bigD = BigInt(d);
  return {
    // FIPS 203 §4.2.1: Compress_d(x) = round((2^d / q) * x) mod 2^d, evaluated over the
    // rationals with ties rounded up. The `mod 2^d` is applied by the caller's mask.
    encode: (i: number) => Number((2n * (BigInt(i) << bigD) + bigQ) / twoQ),
    // const decompress = (i: number) => round((Q / 2 ** d) * i);
    decode: (i: number) => (i * Q + a) >>> d,
  };
};

// Raw ByteEncode_d / ByteDecode_d from FIPS 203 operate on d-bit words directly.
// That differs from `polyCoder(d)` for d<12, where noble folds packing together with the lossy
// ciphertext compression step used by u/v. Tests that exercise the spec's raw packing surface need
// this exact non-lossy variant instead.
const byteCoder = (d: number) =>
  crystals.bitsCoder(
    d,
    d === 12
      ? { encode: (i: number) => i, decode: (i: number) => (i >= Q ? i - Q : i) }
      : { encode: (i: number) => i, decode: (i: number) => i }
  );

// NOTE: we merge encoding and compress because it is faster, also both require same d param
// d=12 is the ByteEncode12/ByteDecode12 path rather than compression, and caller-side
// public-key modulus checks route through this helper's decode/encode roundtrip.
// Converts between bytes and d-bits compressed representation.
// Kinda like convertRadix2 from @scure/base.
// decode(encode(t)) == t, but there is loss of information on encode(decode(t))
const polyCoder = (d: number) => (d === 12 ? byteCoder(12) : crystals.bitsCoder(d, compress(d)));

// Poly is mod Q, so 12 bits
type Poly = Uint16Array;

// Coefficients always stay reduced in [0, Q) here (samplers, NTT and coders all reduce),
// so one conditional correction replaces the generic mod().
function polyAdd(a_: TArg<Poly>, b_: TArg<Poly>) {
  const a = a_ as Poly;
  const b = b_ as Poly;
  // Mutates `a` in place; callers must pass two N=256 polynomials.
  for (let i = 0; i < N; i++) {
    const r = a[i] + b[i]; // a += b
    a[i] = r >= Q ? r - Q : r;
  }
}
function polySub(a_: TArg<Poly>, b_: TArg<Poly>) {
  const a = a_ as Poly;
  const b = b_ as Poly;
  // Mutates `a` in place; callers must pass two N=256 polynomials.
  for (let i = 0; i < N; i++) {
    const r = a[i] - b[i]; // a -= b
    a[i] = r < 0 ? r + Q : r;
  }
}

// FIPS-203: Computes the product of two degree-one polynomials with respect to a quadratic modulus
function BaseCaseMultiply(a0: number, a1: number, b0: number, b1: number, zeta: number) {
  // `zeta` here is Algorithm 11's γ = ζ^(2BitRev_7(i)+1).
  // Reduce a1*b1 before multiplying by zeta: a1*b1*zeta would reach ~2^35, forcing JS engines
  // into slow float fmod; with the extra reduction every intermediate fits int32.
  const c0 = crystals.mod(crystals.mod(a1 * b1) * zeta + a0 * b0);
  const c1 = crystals.mod(a0 * b1 + a1 * b0);
  return { c0, c1 };
}

// FIPS-203: Computes the product (in the ring Tq) of two NTT representations.
// Works in place on `f`; `g` is read-only and both inputs must already be in NTT form.
function MultiplyNTTs(f_: TArg<Poly>, g_: TArg<Poly>): TRet<Poly> {
  const f = f_ as Poly;
  const g = g_ as Poly;
  for (let i = 0; i < N / 2; i++) {
    let z = crystals.nttZetas[64 + (i >> 1)];
    if (i & 1) z = -z;
    const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
    f[2 * i + 0] = c0;
    f[2 * i + 1] = c1;
  }
  return f as TRet<Poly>;
}

type PRF = (l: number, key: Uint8Array, nonce: number) => Uint8Array;

/**
 * Prepared (pre-expanded) ML-KEM public key. Experimental prototype.
 * Caches only public data: packed ek, the expanded matrix Â, decoded t̂ and H(ek). No secret
 * material is retained between calls; secret keys passed to `decapsulate` are decoded and wiped
 * per call, exactly like the one-shot API. `clean()` wipes the expanded Â/t̂ cache; the packed
 * public key and H(ek) are public and are not wiped. The object must not be used afterwards.
 */
export type KEMPrepared = {
  /**
   * Detached copy of the source public key. Treat as read-only while the prepared object is in use.
   * Callers may wipe it after final use; any mutation invalidates subsequent operations.
   */
  publicKey: Uint8Array;
  /** Same as `KEM.encapsulate`, minus per-call ek re-validation and Â re-expansion. */
  encapsulate: (msg?: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
  /**
   * Same as `KEM.decapsulate`; throws if `secretKey` does not embed this public key.
   * The embedded-ek byte comparison plus stored-hash comparison is equivalent to the
   * FIPS 203 §7.3 hash input check.
   */
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  /** Wipe cached (public) data. */
  clean: () => void;
};
/** KEM with prepared-key support. */
export type MLKEM = KEM & { prepare: (publicKey: Uint8Array) => KEMPrepared };

type XofGet = ReturnType<ReturnType<XOF>['get']>;

type KyberOpts = KEMParam & {
  HASH256: CHash;
  HASH512: CHash;
  KDF: CHash<any, { dkLen?: number }>;
  XOF: XOF; // (seed: Uint8Array, len: number, x: number, y: number) => Uint8Array;
  PRF: PRF;
};

// Return poly in NTT representation
function SampleNTT(xof_: TArg<XofGet>): TRet<Poly> {
  const xof = xof_ as XofGet;
  // The reader must already bind the Algorithm 7 seed||j||i bytes
  // and return block lengths divisible by 3.
  const r: Poly = new Uint16Array(N);
  for (let j = 0; j < N;) {
    const b = xof();
    if (b.length % 3) throw new Error('SampleNTT: unaligned block');
    for (let i = 0; j < N && i + 3 <= b.length; i += 3) {
      const d1 = ((b[i + 0] >> 0) | (b[i + 1] << 8)) & 0xfff;
      const d2 = ((b[i + 1] >> 4) | (b[i + 2] << 4)) & 0xfff;
      if (d1 < Q) r[j++] = d1;
      if (j < N && d2 < Q) r[j++] = d2;
    }
  }
  return r as TRet<Poly>;
}

// Sampling from the centered binomial distribution
// Returns poly with small coefficients (noise/errors) stored modulo q in ordinary coefficient form.
// Current callers only use Table 2 eta values {2,3} and PRF outputs of exactly 64*eta bytes.
const sampleCBDBytes = (buf: TArg<Uint8Array>, eta: number): TRet<Poly> => {
  const r: Poly = new Uint16Array(N);
  // CBD consumes the PRF bitstream in little-endian byte order; normalize the word view on BE,
  // then swap it back so callers still observe `buf` as read-only.
  const b32 = u32(buf);
  swap32IfBE(b32);
  let len = 0;
  for (let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++) {
    let b = b32[i];
    for (let j = 0; j < 32; j++) {
      bb += b & 1;
      b >>= 1;
      len += 1;
      if (len === eta) {
        t0 = bb;
        bb = 0;
      } else if (len === 2 * eta) {
        r[p++] = crystals.mod(t0 - bb);
        bb = 0;
        len = 0;
      }
    }
  }
  swap32IfBE(b32);
  if (len) throw new Error(`sampleCBD: leftover bits: ${len}`);
  return r as TRet<Poly>;
};

function sampleCBD(
  PRF_: TArg<PRF>,
  seed: TArg<Uint8Array>,
  nonce: number,
  eta: number
): TRet<Poly> {
  const PRF = PRF_ as PRF;
  return sampleCBDBytes(PRF((eta * N) / 4, seed, nonce), eta);
}

// K-PKE
// Internal ML-KEM subroutine only: exact 32-byte `seed` / `msg` inputs
// come from Algorithms 13-15, and the helper mutates decoded temporary
// polynomials in place while leaving caller byte arrays unchanged.
const genKPKE = (opts_: TArg<KyberOpts>) => {
  const opts = opts_ as KyberOpts;
  const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts;
  const poly1 = polyCoder(1);
  const polyV = polyCoder(dv);
  const polyU = polyCoder(du);
  const publicCoder = splitCoder('publicKey', vecCoder(polyCoder(12), K), 32);
  const secretCoder = vecCoder(polyCoder(12), K);
  const cipherCoder = splitCoder('ciphertext', vecCoder(polyU, K), polyV);
  const seedCoder = splitCoder('seed', 32, 32);
  // Algorithm 14 (K-PKE.Encrypt) core, after ek parsing. `tHat` and every poly returned by
  // `getA(i, j)` are treated as disposable scratch: they are mutated in place and wiped/dropped,
  // so callers holding cached copies must pass fresh copies.
  const encryptCore = (
    tHat: TArg<Poly[]>,
    getA: TArg<(i: number, j: number) => Poly>,
    msg: TArg<Uint8Array>,
    seed: TArg<Uint8Array>
  ): TRet<Uint8Array> => {
    const rHat = [];
    for (let i = 0; i < K; i++) rHat.push(crystals.NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
    const tmp2 = new Uint16Array(N);
    const u = [];
    for (let i = 0; i < K; i++) {
      const e1 = sampleCBD(PRF, seed, K + i, ETA2);
      const tmp = new Uint16Array(N);
      for (let j = 0; j < K; j++) {
        const aij = getA(i, j); // A[j][i], inplace transpose access
        polyAdd(tmp, MultiplyNTTs(aij, rHat[j])); // t += aij * rHat[j]
      }
      polyAdd(e1, crystals.NTT.decode(tmp)); // e1 += tmp
      u.push(e1);
      polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i])); // t2 += tHat[i] * rHat[i]
      cleanBytes(tmp);
    }
    const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
    polyAdd(e2, crystals.NTT.decode(tmp2)); // e2 += tmp2
    const v = poly1.decode(msg); // encode plaintext m into polynomial v
    polyAdd(v, e2); // v += e2
    cleanBytes(tHat, rHat, tmp2, e2);
    return cipherCoder.encode([u, v]) as TRet<Uint8Array>;
  };
  return {
    secretCoder,
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      cipherText: cipherCoder.bytesLen,
    },
    keygen: (seed: TArg<Uint8Array>) => {
      abytes(seed, 32, 'seed');
      const seedDst = new Uint8Array(33);
      seedDst.set(seed);
      // FIPS 203 Algorithm 13 appends the parameter-set byte `k`
      // before `G(d || k)`, so expanding the same 32-byte seed
      // under a different ML-KEM parameter set yields unrelated keys.
      seedDst[32] = K;
      const seedHash = HASH512(seedDst);

      const [rho, sigma] = seedCoder.decode(seedHash);
      const sHat: Poly[] = [];
      const tHat: Poly[] = [];
      for (let i = 0; i < K; i++) sHat.push(crystals.NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
      const x = XOF(rho);
      for (let i = 0; i < K; i++) {
        const e = crystals.NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
        for (let j = 0; j < K; j++) {
          const aji = SampleNTT(x.get(j, i)); // A[i][j], inplace
          polyAdd(e, MultiplyNTTs(aji, sHat[j]));
        }
        tHat.push(e); // t ← A ◦ s + e
      }
      x.clean();
      const res = {
        publicKey: publicCoder.encode([tHat, rho]),
        secretKey: secretCoder.encode(sHat),
      };
      cleanBytes(rho, sigma, sHat, tHat, seedDst, seedHash);
      return res;
    },
    encrypt: (
      publicKey: TArg<Uint8Array>,
      msg: TArg<Uint8Array>,
      seed: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
      const [tHat, rho] = publicCoder.decode(publicKey);
      const x = XOF(rho);
      const res = encryptCore(tHat as Poly[], (i, j) => SampleNTT(x.get(i, j)) as Poly, msg, seed);
      x.clean();
      return res;
    },
    // Expands the full Â matrix (public data derived from rho) once, so repeated encryptions
    // against the same ek skip the K² SampleNTT XOF expansions. Cached polys are copied per
    // call because encryptCore mutates its inputs in place.
    prepare: (publicKey: TArg<Uint8Array>) => {
      const [tHat, rho] = publicCoder.decode(publicKey);
      const x = XOF(rho);
      const A: Poly[] = [];
      for (let i = 0; i < K; i++)
        for (let j = 0; j < K; j++) A.push(SampleNTT(x.get(i, j)) as Poly);
      x.clean();
      return {
        encrypt: (msg: TArg<Uint8Array>, seed: TArg<Uint8Array>): TRet<Uint8Array> =>
          encryptCore(
            (tHat as Poly[]).map((p) => p.slice() as Poly),
            (i, j) => A[i * K + j].slice() as Poly,
            msg,
            seed
          ),
        clean: () => cleanBytes(tHat as Poly[], A),
      };
    },
    decrypt: (cipherText: TArg<Uint8Array>, privateKey: TArg<Uint8Array>): TRet<Uint8Array> => {
      const [u, v] = cipherCoder.decode(cipherText);
      const sk = secretCoder.decode(privateKey); // s  ← ByteDecode_12(dkPKE)
      const tmp = new Uint16Array(N);
      // tmp += sk[i] * u[i]
      for (let i = 0; i < K; i++) polyAdd(tmp, MultiplyNTTs(sk[i], crystals.NTT.encode(u[i])));
      polySub(v, crystals.NTT.decode(tmp)); // w = v' - tmp
      // `v` now holds w, from which the plaintext is just a 1-bit threshold away, so wipe it too.
      // encode() allocates its own buffer, so the returned bytes do not alias `v`.
      const res = poly1.encode(v) as TRet<Uint8Array>;
      cleanBytes(tmp, sk, u, v);
      return res;
    },
  };
};

/**
 * Public ML-KEM wrapper over the internal K-PKE subroutine.
 * `keygen(seed)` and `encapsulate(publicKey, msg)` are deterministic/test-oriented hooks that map
 * more directly to Algorithms 16-17 than to the pure no-input / random-internal Algorithms 19-20.
 * `encapsulate`'s optional `msg` is the 32-byte message randomness `m` of Algorithm 17, the
 * pre-image the shared secret is derived from, NOT a plaintext to encrypt: ML-KEM is a key
 * encapsulation mechanism, not a cipher. Omit it to draw fresh randomness; pass it only to
 * reproduce a known-answer vector, and only as 32 uniformly random bytes, since a low-entropy or
 * reused value makes the shared secret predictable. The same holds for `keygen`'s optional `seed`.
 * decapsulate() tries to follow the Algorithms 18/21 implicit-reject structure as closely as
 * practical here by re-encrypting, comparing ciphertexts, and combining `Khat` (match) and
 * `Kbar` (mismatch) through the branch-free {@link selectSharedSecret} mask, then zeroizing
 * both candidates unconditionally; JS/JIT still provides no constant-time guarantees for that
 * path — removing the source-level branch does not make the compiled path constant-time.
 */
function createKyber(opts: TArg<KyberOpts>): TRet<MLKEM> {
  const rawOpts = opts as KyberOpts;
  const KPKE = genKPKE(rawOpts);
  const { HASH256, HASH512, KDF } = rawOpts;
  const { secretCoder: KPKESecretCoder, lengths } = KPKE;
  const secretCoder = splitCoder('secretKey', lengths.secretKey, lengths.publicKey, 32, 32);
  const msgLen = 32;
  const seedLen = 64;
  // FIPS-203 includes additional verification check for modulus
  const validateModulus = (publicKey: TArg<Uint8Array>, fn: string) => {
    const eke = (publicKey as Uint8Array).subarray(0, 384 * rawOpts.K);
    // Copy because of inplace encoding
    const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes(eke)));
    // (Modulus check.) Perform the computation ek ← ByteEncode12(ByteDecode12(eke)).
    // If ek = ̸ eke, the input is invalid. (See Section 4.2.1.)
    const ok = equalBytes(ek, eke);
    cleanBytes(ek);
    if (!ok) throw new Error(`ML-KEM.${fn}: wrong publicKey modulus`);
  };
  const kemLengths = Object.freeze({
    ...lengths,
    seed: 64,
    msg: msgLen,
    msgRand: msgLen,
    secretKey: secretCoder.bytesLen,
  });
  return Object.freeze({
    info: Object.freeze({ type: 'ml-kem' }),
    lengths: kemLengths,
    keygen: (seed?: TArg<Uint8Array>) => {
      // A generated seed carries z (the implicit-rejection secret) and must be wiped once the
      // secret key holds a copy, matching ml-dsa / slh-dsa / falcon keygen. A caller-supplied
      // seed is the caller's to manage (and the immutability test requires it stay untouched).
      const ownSeed = seed === undefined;
      const s = ownSeed ? randomBytes(seedLen) : (seed as TArg<Uint8Array>);
      let sk: Uint8Array | undefined;
      let publicKeyHash: Uint8Array | undefined;
      try {
        abytes(s, seedLen, 'seed');
        const keys = KPKE.keygen(s.subarray(0, 32));
        const publicKey = keys.publicKey;
        sk = keys.secretKey as Uint8Array;
        publicKeyHash = HASH256(publicKey);
        // (dkPKE||ek||H(ek)||z)
        const secretKey = secretCoder.encode([sk, publicKey, publicKeyHash, s.subarray(32)]);
        return {
          publicKey: publicKey as TRet<Uint8Array>,
          secretKey: secretKey as TRet<Uint8Array>,
        };
      } finally {
        if (sk !== undefined) cleanBytes(sk);
        if (publicKeyHash !== undefined) cleanBytes(publicKeyHash);
        if (ownSeed) cleanBytes(s);
      }
    },
    getPublicKey: (secretKey: TArg<Uint8Array>): TRet<Uint8Array> => {
      const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
      return Uint8Array.from(publicKey) as TRet<Uint8Array>;
    },
    encapsulate: (publicKey: TArg<Uint8Array>, msg?: TArg<Uint8Array>) => {
      // A generated message is the preimage of the shared secret (K = G(m || H(ek))[0:32]) and
      // must be wiped. A caller-supplied message is the deterministic-randomness hook and the
      // caller's to manage (the immutability test requires it stay untouched).
      const ownMsg = msg === undefined;
      // LOCAL MODIFICATION (F203-11): sampleRandomness instead of randomBytes, so an RBG
      // failure raises RbgFailureError rather than an opaque host error. Only the
      // module-sampled branch changes; a caller-supplied message is untouched.
      const m = ownMsg ? sampleRandomness(msgLen) : (msg as TArg<Uint8Array>);
      let kr: Uint8Array | undefined;
      try {
        abytes(publicKey, lengths.publicKey, 'publicKey');
        abytes(m, msgLen, 'message');
        validateModulus(publicKey, 'encapsulate');
        // derive randomness
        kr = HASH512.create().update(m).update(HASH256(publicKey)).digest();
        const cipherText = KPKE.encrypt(publicKey, m, kr.subarray(32, 64));
        return {
          cipherText: cipherText as TRet<Uint8Array>,
          sharedSecret: kr.subarray(0, 32) as TRet<Uint8Array>,
        };
      } finally {
        if (kr !== undefined) cleanBytes(kr.subarray(32));
        if (ownMsg) cleanBytes(m);
      }
    },
    decapsulate: (cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array>): TRet<Uint8Array> => {
      abytes(secretKey, secretCoder.bytesLen, 'secretKey'); // 768*k + 96
      abytes(cipherText, lengths.cipherText, 'cipherText'); // 32(du*k + dv)
      // test ← H(dk[384𝑘 ∶ 768𝑘 + 32])) .
      const k768 = secretCoder.bytesLen - 96;
      const start = k768 + 32;
      const test = HASH256(secretKey.subarray(k768 / 2, start));
      // If test ≠ dk[768𝑘 + 32 ∶ 768𝑘 + 64], then input checking has failed.
      if (!equalBytes(test, secretKey.subarray(start, start + 32)))
        throw new Error('invalid secretKey: hash check failed');
      const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
      const msg = KPKE.decrypt(cipherText, sk);
      // derive randomness, Khat, rHat = G(mHat || h)
      const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
      const Khat = kr.subarray(0, 32);
      // re-encrypt using the derived randomness
      const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
      // if ciphertexts do not match, “implicitly reject”
      const isValid = equalBytes(cipherText, cipherText2);
      const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
      // LOCAL MODIFICATION (F203-18). Upstream selected and cleaned with ternaries on the
      // secret flag: `!isValid ? Khat : Kbar` / `isValid ? Khat : Kbar`. Those are
      // source-level branches whose condition is secret intermediate data, and which decide
      // which heap object survives. selectSharedSecret replaces them with byte-wise mask
      // arithmetic, so both candidates are read in full and both are destroyed
      // unconditionally — there is no longer a branch choosing between them.
      // kr[32:64] is the derived K-PKE encryption randomness: wipe it like encapsulate() does.
      const sharedSecret = selectSharedSecret(isValid, Khat, Kbar);
      cleanBytes(msg, cipherText2, kr.subarray(32), Khat, Kbar);
      return sharedSecret as TRet<Uint8Array>;
    },
    /**
     * Experimental prototype: pre-expand a public key so repeated encapsulate/decapsulate
     * against the same key skip re-validation, H(ek), t̂ decoding and the K² SampleNTT
     * XOF expansions of Â. Only public data is cached; see {@link KEMPrepared}.
     */
    prepare: (publicKey: TArg<Uint8Array>): TRet<KEMPrepared> => {
      abytes(publicKey, lengths.publicKey, 'publicKey');
      validateModulus(publicKey, 'prepare');
      const ek = copyBytes(publicKey); // detach from the caller before caching
      const publicKeyHash = HASH256(ek);
      const cached = KPKE.prepare(ek);
      return Object.freeze({
        publicKey: ek as TRet<Uint8Array>,
        encapsulate: (msg?: TArg<Uint8Array>) => {
          // As in the non-prepared encapsulate: a generated message is the shared-secret
          // preimage and is wiped; a caller-supplied one is left untouched.
          const ownMsg = msg === undefined;
          // LOCAL MODIFICATION (F203-11): see the note at the non-prepared encapsulate.
          const m = ownMsg ? sampleRandomness(msgLen) : (msg as TArg<Uint8Array>);
          let kr: Uint8Array | undefined;
          try {
            abytes(m, msgLen, 'message');
            kr = HASH512.create().update(m).update(publicKeyHash).digest();
            const cipherText = cached.encrypt(m, kr.subarray(32, 64));
            return {
              cipherText: cipherText as TRet<Uint8Array>,
              sharedSecret: kr.subarray(0, 32) as TRet<Uint8Array>,
            };
          } finally {
            if (kr !== undefined) cleanBytes(kr.subarray(32));
            if (ownMsg) cleanBytes(m);
          }
        },
        decapsulate: (
          cipherText: TArg<Uint8Array>,
          secretKey: TArg<Uint8Array>
        ): TRet<Uint8Array> => {
          abytes(secretKey, secretCoder.bytesLen, 'secretKey');
          abytes(cipherText, lengths.cipherText, 'cipherText');
          const [sk, ekEmbedded, storedHash, z] = secretCoder.decode(secretKey);
          // Under KEMPrepared's read-only publicKey contract, bind dk to the prepared key.
          // Together with publicKeyHash = H(ek) computed in prepare(), this is equivalent to (and
          // stronger than) FIPS 203 §7.3's `H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]`.
          if (!equalBytes(ekEmbedded, ek) || !equalBytes(storedHash, publicKeyHash))
            throw new Error('ML-KEM.decapsulate: secretKey does not match prepared publicKey');
          const msg = KPKE.decrypt(cipherText, sk);
          // derive randomness, Khat, rHat = G(mHat || h)
          const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
          const Khat = kr.subarray(0, 32);
          // re-encrypt using the derived randomness and cached Â/t̂
          const cipherText2 = cached.encrypt(msg, kr.subarray(32, 64));
          // if ciphertexts do not match, “implicitly reject”
          const isValid = equalBytes(cipherText, cipherText2);
          const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
          // LOCAL MODIFICATION (F203-18): see the note at the non-prepared decapsulate.
          const sharedSecret = selectSharedSecret(isValid, Khat, Kbar);
          cleanBytes(msg, cipherText2, kr.subarray(32), Khat, Kbar);
          return sharedSecret as TRet<Uint8Array>;
        },
        clean: cached.clean,
      }) as TRet<KEMPrepared>;
    },
  });
}

// FIPS 203's PRF_eta binding: current callers use only 32-byte keys, one-byte nonces,
// and dkLen values {128, 192}; out-of-range nonce numbers still wrap modulo 256 here.
function shakePRF(dkLen: number, key: TArg<Uint8Array>, nonce: number): TRet<Uint8Array> {
  return shake256
    .create({ dkLen })
    .update(key)
    .update(new Uint8Array([nonce]))
    .digest() as TRet<Uint8Array>;
}

// Fixed ML-KEM hash/XOF bindings. `KDF` here is the spec's fixed 32-byte `J` call,
// and swapping any field changes the scheme rather than tuning an internal dependency.
const opts = /* @__PURE__ */ (() => ({
  HASH256: sha3_256,
  HASH512: sha3_512,
  KDF: shake256,
  XOF: XOF128,
  PRF: shakePRF,
}))();
// Parameter-set instantiation step for the spec's "ML-KEM-x" names; current correctness relies
// on the internal PARAMS rows rather than local validation of arbitrary KEMParam objects.
const mk = (params: KEMParam) =>
  createKyber({
    ...opts,
    ...params,
  });

/**
 * ML-KEM-512: Table 2 row `k=2, η1=3, η2=2, du=10, dv=4`; Table 3 sizes `800/1632/768/32`.
 * The ASD lifecycle note here is external policy guidance, not a FIPS 203 requirement.
 * @example
 * Generate deterministic ML-KEM-512 keys, encapsulate a shared secret, and decapsulate it.
 * ```ts
 * import { ml_kem512 } from '@noble/post-quantum/ml-kem.js';
 * const seed = new Uint8Array(ml_kem512.lengths.seed!);
 * const { secretKey, publicKey } = ml_kem512.keygen(seed);
 * const msg = new Uint8Array(ml_kem512.lengths.msgRand!);
 * const { cipherText, sharedSecret } = ml_kem512.encapsulate(publicKey, msg);
 * const recovered = ml_kem512.decapsulate(cipherText, secretKey);
 * const publicKey2 = ml_kem512.getPublicKey(secretKey);
 * ```
 */
export const ml_kem512: TRet<MLKEM> = /* @__PURE__ */ (() => mk(PARAMS[512]))();
/**
 * ML-KEM-768: Table 2 row `k=3, η1=2, η2=2, du=10, dv=4`; Table 3 sizes `1184/2400/1088/32`.
 * The ASD lifecycle note here is external policy guidance, not a FIPS 203 requirement.
 */
export const ml_kem768: TRet<MLKEM> = /* @__PURE__ */ (() => mk(PARAMS[768]))();
/**
 * ML-KEM-1024: Table 2 row `k=4, η1=2, η2=2, du=11, dv=5`; Table 3 sizes `1568/3168/1568/32`.
 * The ASD lifecycle note here is external policy guidance, not a FIPS 203 requirement.
 */
export const ml_kem1024: TRet<MLKEM> = /* @__PURE__ */ (() => mk(PARAMS[1024]))();

// NOTE: for tests only, don't use. This keeps the exact internal ML-KEM math surfaces available
// without re-implementing them in separate test code.
export const __tests: any = /* @__PURE__ */ (() =>
  Object.freeze({
    Compress_d: (x: number, d: number) => {
      if (d < 1 || d > 11) throw new Error(`Compress_d: expected d in [1..11], got ${d}`);
      return compress(d).encode(x) & getMask(d);
    },
    Decompress_d: (y: number, d: number) => {
      if (d < 1 || d > 11) throw new Error(`Decompress_d: expected d in [1..11], got ${d}`);
      return compress(d).decode(y);
    },
    ByteEncode_d: (F: TArg<Uint16Array>, d: number) => {
      if (d < 1 || d > 12) throw new Error(`ByteEncode_d: expected d in [1..12], got ${d}`);
      return byteCoder(d).encode(F as TRet<Uint16Array>);
    },
    ByteDecode_d: (B: TArg<Uint8Array>, d: number) => {
      if (d < 1 || d > 12) throw new Error(`ByteDecode_d: expected d in [1..12], got ${d}`);
      return byteCoder(d).decode(B);
    },
    NTT: (f: TArg<Uint16Array>) => crystals.NTT.encode(Uint16Array.from(f)),
    NTT_inv: (fHat: TArg<Uint16Array>) => crystals.NTT.decode(Uint16Array.from(fHat)),
    MultiplyNTTs: (fHat: TArg<Uint16Array>, gHat: TArg<Uint16Array>) =>
      MultiplyNTTs(Uint16Array.from(fHat), Uint16Array.from(gHat)),
    SamplePolyCBD: (B: TArg<Uint8Array>, eta: number) => {
      abytes(B, 64 * eta, 'B');
      return sampleCBDBytes(B, eta);
    },
    SampleNTT: (B: TArg<Uint8Array>) => {
      abytes(B, 34, 'B');
      const xof = XOF128(B.subarray(0, 32));
      try {
        return SampleNTT(xof.get(B[32], B[33]));
      } finally {
        xof.clean();
      }
    },
  }))();
