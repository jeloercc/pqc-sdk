import { describe, expect, it } from 'vitest';

/**
 * F204-13 regression suite — integer-only Decompose / Power2Round.
 *
 * FIPS 204 §3.6.4: "Implementations of ML-DSA shall not use floating-point arithmetic, as
 * rounding errors in floating point operations may lead to incorrect results in some
 * cases." That is a `shall` (FIPS 204 §2.1), and it constrains the *method*, not the
 * outcome — the upstream expressions were bit-exact and still breached it.
 *
 * Upstream 0.7.1 used `Math.floor(x / y)` at four sites. In JavaScript `/` is always
 * IEEE-754 double division and `Math.floor` does not change the arithmetic performed, so
 * every one of them was a floating-point operation.
 *
 * The domain is enumerated exhaustively, not sampled: `q = 8380417`, and `decompose` /
 * `Power2Round` both reduce their input with `mod q` first, so `rPlus` ranges over the
 * whole of Z_q. `decompose` is checked for both GAMMA2 values that FIPS 204 Table 1
 * assigns — (q-1)/88 for ML-DSA-44 and (q-1)/32 for ML-DSA-65/87 — giving roughly 25
 * million evaluations in total. Zero discrepancies is the only passing result.
 *
 * The arithmetic is reproduced here rather than imported because `decompose` and
 * `Power2Round` are closure-local to `getDilithium` and not exported, even on the
 * `__tests` surface. That is a real limitation of this suite and is stated rather than
 * papered over: it verifies the *expressions*, and the source-text test at the end is what
 * ties them to the shipped file.
 */

const Q = 8380417;
const D = 13;

/** FIPS 204 Table 1: gamma2 = (q-1)/88 for ML-DSA-44, (q-1)/32 for ML-DSA-65 and -87. */
const GAMMA2_1_ORIGINAL = Math.floor((Q - 1) / 88) | 0;
const GAMMA2_2_ORIGINAL = Math.floor((Q - 1) / 32) | 0;

/** The replacements, as they appear in ../ml-dsa.ts. */
const GAMMA2_1_INTEGER = Number(BigInt(Q - 1) / 88n) | 0;
const GAMMA2_2_INTEGER = ((Q - 1) >>> 5) | 0;

/** `crystals.mod` / `crystals.smod`, reproduced from ../ml-kem/_crystals.ts. */
const mod = (a: number, modulo = Q): number => {
  const result = (a % modulo) | 0;
  return (result >= 0 ? result | 0 : (modulo + result) | 0) | 0;
};
const smod = (a: number, modulo = Q): number => {
  const r = mod(a, modulo) | 0;
  return (r > modulo >> 1 ? (r - modulo) | 0 : r) | 0;
};

describe('F204-13: gamma2 constants are computed without floating-point division', () => {
  it('reproduces both FIPS 204 Table 1 values exactly', () => {
    expect(GAMMA2_1_INTEGER).toBe(GAMMA2_1_ORIGINAL);
    expect(GAMMA2_2_INTEGER).toBe(GAMMA2_2_ORIGINAL);
    // Pinned literally so a future edit cannot drift both sides together.
    expect(GAMMA2_1_INTEGER).toBe(95232);
    expect(GAMMA2_2_INTEGER).toBe(261888);
  });
});

describe('F204-13: decompose is integer-only and bit-exact over all of Z_q', () => {
  it.each([
    ['ML-DSA-44', GAMMA2_1_ORIGINAL, 44],
    ['ML-DSA-65/87', GAMMA2_2_ORIGINAL, 16],
  ])(
    '%s (gamma2 = %i): matches the original across the full domain',
    (_name, GAMMA2, hintM) => {
      const twoGamma2 = 2 * GAMMA2;
      const twoGamma2Big = BigInt(twoGamma2);

      // HINT_M = (q-1)/(2*gamma2), hoisted per parameter set in the implementation.
      expect(Number(BigInt(Q - 1) / twoGamma2Big)).toBe(Math.floor((Q - 1) / twoGamma2));
      expect(Number(BigInt(Q - 1) / twoGamma2Big)).toBe(hintM);

      const mismatches: string[] = [];
      let evaluated = 0;

      for (let r = 0; r < Q; r++) {
        const rPlus = mod(r);
        const r0 = smod(rPlus, twoGamma2) | 0;
        // FIPS 204 Algorithm 36's top-bucket fold returns before the division; unchanged.
        if (rPlus - r0 === Q - 1) continue;
        evaluated++;

        const original = Math.floor((rPlus - r0) / twoGamma2) | 0;
        const integerOnly = Number(BigInt(rPlus - r0) / twoGamma2Big) | 0;

        if (original !== integerOnly && mismatches.length < 10) {
          mismatches.push(`r=${r}: original ${original}, integer-only ${integerOnly}`);
        }
      }

      expect(mismatches).toEqual([]);
      expect(evaluated).toBeGreaterThan(8_000_000);
    },
    120_000,
  );

  it('the dividend is always an exact multiple of 2*gamma2, so truncation cannot round', () => {
    // The property the replacement relies on. If it ever failed, BigInt's truncating
    // division and the original's Math.floor could still agree by accident on the tested
    // values while differing elsewhere — so it is checked directly, not inferred.
    for (const GAMMA2 of [GAMMA2_1_ORIGINAL, GAMMA2_2_ORIGINAL]) {
      const twoGamma2 = 2 * GAMMA2;
      const offenders: string[] = [];
      for (let r = 0; r < Q; r += 997) {
        const rPlus = mod(r);
        const r0 = smod(rPlus, twoGamma2) | 0;
        if (rPlus - r0 === Q - 1) continue;
        if ((rPlus - r0) % twoGamma2 !== 0 && offenders.length < 5) offenders.push(`r=${r}`);
        if (rPlus - r0 < 0 && offenders.length < 5) offenders.push(`negative at r=${r}`);
      }
      expect(offenders).toEqual([]);
    }
  }, 30_000);
});

describe('F204-13: Power2Round is integer-only and bit-exact over all of Z_q', () => {
  it('matches the original across the full domain', () => {
    // Here the divisor is 2^13, so FIPS 204 §3.6.4's own guidance applies: "If y is a power
    // of two, it may be more efficient to use bit shift operations than integer division."
    const mismatches: string[] = [];

    for (let r = 0; r < Q; r++) {
      const rPlus = mod(r);
      const r0 = smod(rPlus, 2 ** D) | 0;

      const original = Math.floor((rPlus - r0) / 2 ** D) | 0;
      const integerOnly = ((rPlus - r0) >>> D) | 0;

      if (original !== integerOnly && mismatches.length < 10) {
        mismatches.push(`r=${r}: original ${original}, integer-only ${integerOnly}`);
      }
    }

    expect(mismatches).toEqual([]);
  }, 120_000);

  it('the shift operand stays non-negative and below 2^31, so `>>>` is exact', () => {
    // `>>>` coerces through ToUint32. A negative or oversized operand would wrap silently
    // rather than fail, so the precondition is asserted rather than assumed.
    let min = Infinity;
    let max = -Infinity;
    for (let r = 0; r < Q; r += 13) {
      const rPlus = mod(r);
      const value = rPlus - (smod(rPlus, 2 ** D) | 0);
      if (value < min) min = value;
      if (value > max) max = value;
    }
    expect(min).toBeGreaterThanOrEqual(0);
    expect(max).toBeLessThan(2 ** 31);
  }, 30_000);
});

describe('F204-13: no floating-point division remains in the shipped source', () => {
  it('the rounding sites in ml-dsa.ts use BigInt or a shift, never `Math.floor(x / y)`', async () => {
    // A behavioural test cannot observe *how* a value was computed, and this requirement is
    // about method — the upstream expressions produced identical output and still breached
    // §3.6.4. Only the source can be checked, so a future edit reintroducing the division
    // fails here rather than silently re-opening the finding.
    const { readFileSync } = await import('node:fs');
    const file = readFileSync(new URL('../ml-dsa.ts', import.meta.url), 'utf8');
    const code = file
      .split('\n')
      .filter((line) => {
        const t = line.trimStart();
        return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
      })
      .join('\n');

    // The four corrected sites, by their original shapes.
    expect(code).not.toMatch(/Math\.floor\(\(Q - 1\) \/ 88\)/);
    expect(code).not.toMatch(/Math\.floor\(\(Q - 1\) \/ 32\)/);
    expect(code).not.toMatch(/Math\.floor\(\(rPlus - r0\) \/ \(2 \* GAMMA2\)\)/);
    expect(code).not.toMatch(/Math\.floor\(\(rPlus - r0\) \/ 2 \*\* D\)/);
    expect(code).not.toMatch(/Math\.floor\(\(Q - 1\) \/ \(2 \* GAMMA2\)\)/);

    // And no `Math.floor` of any division survives anywhere in the executable source.
    expect(code).not.toMatch(/Math\.floor\([^)]*\//);

    // The replacements are present.
    expect(code).toContain('Number(BigInt(Q - 1) / 88n)');
    expect(code).toContain('((Q - 1) >>> 5)');
    expect(code).toContain('Number(BigInt(rPlus - r0) / TWO_GAMMA2)');
    expect(code).toContain('((rPlus - r0) >>> D)');
  });
});
