import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { __tests } from '../ml-kem.js';

/**
 * Upstream declares `__tests` as `any`, and the vendored file carries `@ts-nocheck`, so
 * nothing constrains it at the import site. Narrow it once here rather than letting `any`
 * spread through every assertion below.
 */
interface MlKemMathSurface {
  /** FIPS 203 §4.2.1 Compress_d, already masked into Z_(2^d). */
  Compress_d(x: number, d: number): number;
  /** FIPS 203 §4.2.1 Decompress_d. */
  Decompress_d(y: number, d: number): number;
}

const vendored = __tests as MlKemMathSurface;

/**
 * F203-19 regression suite.
 *
 * `Compress_d` in the vendored ML-KEM was re-implemented with BigInt to remove IEEE-754
 * floating-point division, which FIPS 203 §3.3 ("Implementations of ML-KEM shall not use
 * floating-point arithmetic") and §4.2.1 ("Floating-point computations shall not be used")
 * both prohibit. Both are `shall` statements — requirements, per FIPS 203 §2.1.
 *
 * Removing floating-point arithmetic is only safe if the replacement produces identical
 * output. This suite establishes that over the *complete* input domain rather than a
 * sample: q = 3329 and d ranges over [1, 11], so there are 3329 × 11 = 36,619 pairs. That
 * is small enough to enumerate exhaustively in CI, so nothing here is probabilistic.
 *
 * Two independent references are checked, because agreeing with the old code only proves
 * the change was inert — it does not prove either version was ever right:
 *
 *   1. the original floating-point expression shipped in @noble/post-quantum 0.7.1, and
 *   2. the FIPS 203 §4.2.1 definition evaluated in exact rational arithmetic.
 *
 * Zero discrepancies against both is the only passing result.
 */

const Q = 3329;
const D_VALUES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] as const;

/**
 * The expression exactly as it shipped in @noble/post-quantum 0.7.1:
 * `encode: (i) => ((i << d) + Q / 2) / Q`.
 *
 * `Q / 2` is 1664.5 and the outer `/ Q` divides by a non-power-of-two, so both operations
 * are IEEE-754 double arithmetic. It is reproduced here — and *only* here, never in
 * production code — to prove the replacement did not change any output.
 */
function originalFloatingPointEncode(i: number, d: number): number {
  return ((i << d) + Q / 2) / Q;
}

/**
 * FIPS 203 §4.2.1: Compress_d(x) = round((2^d / q) · x) mod 2^d, with the division and
 * rounding "performed in the set of rational numbers" and ties rounded up.
 *
 * Evaluated entirely in BigInt so the reference itself is free of the rounding behaviour
 * under test. round_half_up(a/b) = floor((2a + b) / 2b) for a, b >= 0.
 */
function specCompress(i: number, d: number): number {
  const twoPowD = 1n << BigInt(d);
  const numerator = 2n * BigInt(i) * twoPowD + BigInt(Q);
  return Number((((numerator / BigInt(2 * Q)) % twoPowD) + twoPowD) % twoPowD);
}

/** The mask every caller applies (`bitsCoder` and `__tests.Compress_d` alike). */
const maskFor = (d: number): number => (1 << d) - 1;

describe('F203-19: vendored Compress_d is floating-point free and bit-exact', () => {
  it('matches the original floating-point implementation on all 36,619 domain pairs', () => {
    const mismatches: string[] = [];
    let checked = 0;

    for (const d of D_VALUES) {
      const mask = maskFor(d);
      for (let i = 0; i < Q; i++) {
        checked++;
        const expected = originalFloatingPointEncode(i, d) & mask;
        const actual = vendored.Compress_d(i, d);
        // Collect rather than assert inside the loop: on a regression we want to know the
        // scale of the divergence, not just the first coordinate that hit it.
        if (actual !== expected && mismatches.length < 10) {
          mismatches.push(`d=${d} i=${i}: expected ${expected}, got ${actual}`);
        }
      }
    }

    expect(checked).toBe(36_619);
    expect(mismatches).toEqual([]);
  });

  it('matches the FIPS 203 §4.2.1 definition evaluated in exact rational arithmetic', () => {
    const mismatches: string[] = [];

    for (const d of D_VALUES) {
      for (let i = 0; i < Q; i++) {
        const expected = specCompress(i, d);
        const actual = vendored.Compress_d(i, d);
        if (actual !== expected && mismatches.length < 10) {
          mismatches.push(`d=${d} i=${i}: spec says ${expected}, got ${actual}`);
        }
      }
    }

    expect(mismatches).toEqual([]);
  });

  it('always lands inside Z_(2^d), as the standard requires of the output', () => {
    // One assertion at the end rather than three per iteration: 36,619 × 3 expect() calls
    // is slow enough to trip the default 5s timeout, and a collected list reports the
    // scale of a regression instead of only its first coordinate.
    const violations: string[] = [];

    for (const d of D_VALUES) {
      const bound = 1 << d;
      for (let i = 0; i < Q; i++) {
        const y = vendored.Compress_d(i, d);
        if (!Number.isInteger(y) || y < 0 || y >= bound) {
          if (violations.length < 10) violations.push(`d=${d} i=${i}: got ${y}`);
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it('satisfies the FIPS 203 §4.2.1 round-trip property Compress_d(Decompress_d(y)) = y', () => {
    // The standard states this identity holds for all y in Z_(2^d) and all d < 12. It is a
    // property of the pair, so it catches a change to either half.
    const failures: string[] = [];

    for (const d of D_VALUES) {
      for (let y = 0; y < 1 << d; y++) {
        const roundTripped = vendored.Compress_d(vendored.Decompress_d(y, d), d);
        if (roundTripped !== y && failures.length < 10) {
          failures.push(`d=${d} y=${y}: round-tripped to ${roundTripped}`);
        }
      }
    }

    expect(failures).toEqual([]);
  });

  it('is genuinely mutation-sensitive: a wrong rounding rule is detected', () => {
    // Guards the suite itself. If truncation replaced round-half-up, the checks above must
    // fail — otherwise they prove nothing. Truncation differs from rounding whenever the
    // fractional part is >= 1/2, which happens across this domain.
    const truncating = (i: number, d: number): number =>
      Number((BigInt(i) << BigInt(d)) / BigInt(Q)) & maskFor(d);

    let divergences = 0;
    for (const d of D_VALUES) {
      for (let i = 0; i < Q; i++) {
        if (truncating(i, d) !== vendored.Compress_d(i, d)) divergences++;
      }
    }

    expect(divergences).toBeGreaterThan(0);
  });

  it('does not use floating-point arithmetic in the compression source', () => {
    // A behavioural test cannot observe *how* a result was computed, and F203-19 is a
    // requirement about method, not outcome — the old code was bit-exact too, and still
    // breached the standard. So this reads the shipped source and asserts on the text: a
    // future edit that reintroduces `/ Q` fails here rather than silently re-opening the
    // finding. Scoped to the compress() factory alone, since `2 ** (d - 1)` elsewhere is
    // exact in binary and `>>>` is an integer shift.
    const file = readFileSync(new URL('../ml-kem.ts', import.meta.url), 'utf8');
    const start = file.indexOf('const compress = (d: number)');
    expect(start).toBeGreaterThan(-1);
    const body = file.slice(start, file.indexOf('\n};', start));

    // Ignore comment lines: the header deliberately quotes the old expression.
    const code = body
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('//'))
      .join('\n');

    expect(code).not.toMatch(/Q\s*\/\s*2/);
    expect(code).not.toMatch(/\)\s*\/\s*Q/);
    expect(code).toContain('BigInt');
  });
});
