import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { ALGORITHMS, getAlgorithm, keyLengthFor } from './algorithms.js';
import { toBase64Url } from './base64url.js';
import { PqcError } from './errors.js';
import { deserialize } from './keys.js';
import type { ExpectedKey } from './keys.js';
import type { Algorithm, KeyUse, PqcKey } from './types.js';

// Day 2 of the robustness sprint: fuzz the deserialization parser.
//
// `deserialize` is the only function that ingests untrusted input (serialized
// key tokens arriving from clients), so it is the SDK's primary attack surface.
// The single invariant we assert over every hostile input:
//
//   deserialize(input) EITHER returns a structurally valid key whose
//   algorithm / use / byte-length are mutually consistent, OR throws a
//   PqcError — never anything else (no TypeError, no RangeError, no undefined
//   return, no hang). The typed overload deserialize(input, { algorithm, use })
//   honours the same contract.
//
// Determinism: a fixed `seed` makes CI reproducible and replays the same
// counterexample on failure. If fast-check ever finds an input that breaks the
// invariant, that is a real security finding — `assertFailsClosed` throws with
// the exact input so the counterexample is impossible to miss.
const FUZZ = { seed: 0x5eed_1234, numRuns: 1000 } as const;

const PREFIX = 'pqcv1';
const ALGS = Object.keys(ALGORITHMS) as Algorithm[];
const USES: readonly KeyUse[] = ['public', 'secret'] as const;
const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('');

function correctLen(algorithm: Algorithm, use: KeyUse): number {
  return keyLengthFor(getAlgorithm(algorithm), use);
}

function makeToken(algorithm: string, use: string, encoded: string): string {
  return `${PREFIX}.${algorithm}.${use}.${encoded}`;
}

/** Canonical base64url of `byteLen` zero bytes — a valid payload of that length. */
function encodeLen(byteLen: number): string {
  return toBase64Url(new Uint8Array(byteLen));
}

/** Asserts a *returned* key is structurally valid and internally consistent. */
function assertConsistentKey(key: PqcKey, input: string): void {
  const where = `for input ${JSON.stringify(input).slice(0, 120)}`;
  expect(key, where).toBeTypeOf('object');
  expect(key, where).not.toBeNull();
  expect(ALGS, where).toContain(key.algorithm);
  expect(USES, where).toContain(key.use);
  expect(key.bytes, where).toBeInstanceOf(Uint8Array);
  // The length must match the algorithm+use exactly — a key of any other length
  // would be a malformed return, which the invariant forbids.
  expect(key.bytes.length, where).toBe(correctLen(key.algorithm, key.use));
}

/**
 * The core check: `deserialize(input)` must fail closed. It may only return a
 * consistent key or throw a {@link PqcError}. Anything else (a non-PqcError
 * throw, an inconsistent key) is surfaced as a loud failure carrying the exact
 * input, because that is a security finding rather than a test to adjust.
 */
function assertFailsClosed(input: string, expected?: ExpectedKey): void {
  let result: PqcKey;
  try {
    result = expected === undefined ? deserialize(input) : deserialize(input, expected);
  } catch (error) {
    if (error instanceof PqcError) {
      return; // The only acceptable failure mode.
    }
    const name =
      (error as { constructor?: { name?: string } } | null)?.constructor?.name ?? typeof error;
    throw new Error(
      `deserialize threw a non-PqcError (${name}: ${String(error)}) for input ${JSON.stringify(input)}`,
    );
  }
  // It returned: the key must be structurally valid and mutually consistent...
  assertConsistentKey(result, input);
  // ...and, under the typed overload, must match what the caller asserted.
  if (expected !== undefined) {
    expect(result.algorithm, `for input ${JSON.stringify(input)}`).toBe(expected.algorithm);
    expect(result.use, `for input ${JSON.stringify(input)}`).toBe(expected.use);
  }
}

// --- Generators -----------------------------------------------------------

const algSeg = fc.constantFrom<Algorithm>(...ALGS);
const useSeg = fc.constantFrom<KeyUse>(...USES);

// A single dot-delimited segment (dots stripped so it stays one segment).
const segment = fc.string({ maxLength: 24 }).map((s) => s.replace(/\./g, ''));
const unknownAlg = segment.filter((s) => !(ALGS as string[]).includes(s));
const unknownUse = segment.filter((s) => s !== 'public' && s !== 'secret');

// A run of base64url-alphabet characters of arbitrary length — frequently the
// wrong length and/or non-canonical, which is exactly the point.
const b64urlRun = fc
  .array(fc.constantFrom(...B64URL_CHARS), { maxLength: 64 })
  .map((cs) => cs.join(''));

// 1. Arbitrary strings: empty, ASCII, full-unicode (control chars, surrogates),
//    and graphemes. Almost none look like a token.
const arbitraryString = fc.oneof(
  fc.string({ maxLength: 64 }),
  fc.string({ unit: 'binary', maxLength: 64 }),
  fc.string({ unit: 'grapheme', maxLength: 32 }),
  fc.constant(''),
);

// 2. Right prefix, wrong segment count (anything but exactly 4 parts total).
const wrongSegmentCount = fc
  .array(segment, { maxLength: 6 })
  .filter((segs) => segs.length !== 3)
  .map((segs) => [PREFIX, ...segs].join('.'));

// 3. Unknown algorithm, otherwise well-formed.
const unknownAlgToken = fc
  .tuple(unknownAlg, useSeg, b64urlRun)
  .map(([a, u, e]) => makeToken(a, u, e));

// 4. Unknown use, otherwise well-formed.
const unknownUseToken = fc
  .tuple(algSeg, unknownUse, b64urlRun)
  .map(([a, u, e]) => makeToken(a, u, e));

// 5. Valid, canonical base64url that decodes to the wrong byte length (0..64
//    bytes is always far short of any real key).
const wrongLengthToken = fc
  .tuple(algSeg, useSeg, fc.nat({ max: 64 }))
  .map(([a, u, n]) => makeToken(a, u, encodeLen(n)));

// 6. A non-alphabet character injected into the payload (classic base64 +/=,
//    whitespace, control, and multibyte unicode all live outside base64url).
const badChar = fc.constantFrom(
  '!',
  '*',
  '+',
  '/',
  '=',
  ' ',
  '\n',
  '\t',
  '#',
  '%',
  'é',
  '€',
  '\u0000',
);
const invalidB64Token = fc
  .tuple(algSeg, useSeg, b64urlRun, badChar, fc.nat())
  .map(([a, u, run, bad, pos]) => {
    const i = pos % (run.length + 1);
    return makeToken(a, u, run.slice(0, i) + bad + run.slice(i));
  });

// 7. Non-canonical base64url: length % 4 === 2 (one trailing byte) but the four
//    leftover low bits are non-zero, so it is no byte sequence's canonical form.
const nonCanonicalToken = fc
  .tuple(algSeg, useSeg, fc.constantFrom('B', 'C', 'D', 'E', 'F', 'P', '-', '_'))
  .map(([a, u, c]) => makeToken(a, u, `A${c}`));

// 8. The impossible base64url length: length % 4 === 1 decodes to no whole byte.
const impossibleLenToken = fc
  .tuple(algSeg, useSeg, fc.nat({ max: 16 }))
  .map(([a, u, k]) => makeToken(a, u, 'A'.repeat(k * 4 + 1)));

// 9. A random prefix-length slice of a genuinely valid token (truncation).
const truncatedToken = fc.tuple(algSeg, useSeg, fc.nat()).map(([a, u, n]) => {
  const full = makeToken(a, u, encodeLen(correctLen(a, u)));
  return full.slice(0, n % (full.length + 1));
});

// 10. Extra dots / segments injected into an otherwise valid token.
const injectedDotsToken = fc
  .tuple(algSeg, useSeg, fc.nat(), fc.nat({ max: 4 }))
  .map(([a, u, pos, extra]) => {
    const valid = makeToken(a, u, encodeLen(correctLen(a, u)));
    const i = pos % (valid.length + 1);
    return valid.slice(0, i) + '.'.repeat(extra + 1) + valid.slice(i);
  });

// 11. Valid algorithm and use, byte length off by one in each direction.
const offByOneToken = fc
  .tuple(algSeg, useSeg, fc.constantFrom(-1, 1))
  .map(([a, u, delta]) => makeToken(a, u, encodeLen(correctLen(a, u) + delta)));

// 12. A genuinely valid token — exercises the "returns a consistent key" branch
//     so the suite cannot pass vacuously by only ever throwing.
const validToken = fc
  .tuple(algSeg, useSeg)
  .map(([a, u]) => makeToken(a, u, encodeLen(correctLen(a, u))));

const hostileToken = fc.oneof(
  arbitraryString,
  wrongSegmentCount,
  unknownAlgToken,
  unknownUseToken,
  wrongLengthToken,
  invalidB64Token,
  nonCanonicalToken,
  impossibleLenToken,
  truncatedToken,
  injectedDotsToken,
  offByOneToken,
  validToken,
);

const expectedArb = fc.record({ algorithm: algSeg, use: useSeg });

// --- Properties -----------------------------------------------------------

describe('fuzz: deserialize fails closed', () => {
  it('returns a consistent key or throws PqcError — for any hostile input (untyped)', () => {
    fc.assert(
      fc.property(hostileToken, (input) => {
        assertFailsClosed(input);
      }),
      FUZZ,
    );
  });

  it('honours the same invariant under an asserted { algorithm, use } (typed overload)', () => {
    fc.assert(
      fc.property(hostileToken, expectedArb, (input, expected) => {
        assertFailsClosed(input, expected);
      }),
      FUZZ,
    );
  });

  it('never crashes on a pure run of base64url characters of any length', () => {
    // Targets the decoder directly: wrong length, non-canonical, and impossible
    // (% 4 === 1) cases all arise organically from a random alphabet run.
    fc.assert(
      fc.property(algSeg, useSeg, b64urlRun, (a, u, run) => {
        assertFailsClosed(makeToken(a, u, run));
      }),
      FUZZ,
    );
  });
});

// --- Explicit, named regressions for the nastiest hand-picked cases --------

describe('deserialize regression: hand-picked hostile inputs', () => {
  const cases: ReadonlyArray<readonly [name: string, input: string]> = [
    ['empty string', ''],
    ['only the prefix', 'pqcv1'],
    ['prefix with a trailing dot', 'pqcv1.'],
    ['a run of dots', '..........'],
    ['wrong prefix version', 'pqcv2.ml-kem-768.public.AAAA'],
    ['prefix but five segments', 'pqcv1.ml-kem-768.public.AAAA.extra'],
    ['empty algorithm segment', 'pqcv1..public.AAAA'],
    ['empty use segment', 'pqcv1.ml-kem-768..AAAA'],
    ['unknown algorithm', 'pqcv1.rsa-2048.public.AAAA'],
    ['unknown use', 'pqcv1.ml-kem-768.banana.AAAA'],
    ['classic base64 +/ = chars', 'pqcv1.ml-kem-768.public.++//=='],
    ['impossible length (% 4 === 1)', 'pqcv1.ml-kem-768.public.A'],
    ['non-canonical trailing bits', 'pqcv1.ml-kem-768.public.AB'],
    ['embedded null bytes', 'pqcv1.ml-kem-768.public.\u0000\u0000\u0000\u0000'],
    ['unicode in the payload', 'pqcv1.ml-kem-768.public.é€中'],
    ['newline injected into the payload', 'pqcv1.ml-kem-768.public.AAAA\n'],
    ['off-by-one short (1183 bytes)', `pqcv1.ml-kem-768.public.${encodeLen(1183)}`],
    ['off-by-one long (1185 bytes)', `pqcv1.ml-kem-768.public.${encodeLen(1185)}`],
    ['public-length bytes under the secret slot', `pqcv1.ml-kem-768.secret.${encodeLen(1184)}`],
    ['huge payload of invalid characters', `pqcv1.ml-kem-768.public.${'!'.repeat(100_000)}`],
    [
      'huge valid-charset payload of the wrong length',
      `pqcv1.ml-kem-768.public.${'A'.repeat(100_000)}`,
    ],
  ];

  it.each(cases)('fails closed: %s', (_name, input) => {
    assertFailsClosed(input);
    // The typed overload must fail closed on the same input, too.
    assertFailsClosed(input, { algorithm: 'ml-kem-768', use: 'public' });
  });

  it('every truncated prefix of a valid token fails closed', () => {
    const token = makeToken('ml-kem-768', 'public', encodeLen(correctLen('ml-kem-768', 'public')));
    for (let i = 0; i < token.length; i += 1) {
      assertFailsClosed(token.slice(0, i));
    }
    // The full string is the one valid input and must round-trip to a key.
    assertConsistentKey(deserialize(token), token);
  });

  it('a genuinely valid token returns a consistent key (positive control)', () => {
    for (const algorithm of ALGS) {
      for (const use of USES) {
        const token = makeToken(algorithm, use, encodeLen(correctLen(algorithm, use)));
        assertConsistentKey(deserialize(token), token);

        const typed = deserialize(token, { algorithm, use });
        expect(typed.algorithm).toBe(algorithm);
        expect(typed.use).toBe(use);
      }
    }
  });
});
