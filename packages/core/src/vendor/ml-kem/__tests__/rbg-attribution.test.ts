import { afterEach, describe, expect, it, vi } from 'vitest';

import { encapsulateTo, KEM_ALGORITHMS } from '../../../algorithms.js';
import { PqcError } from '../../../errors.js';
import { pqc } from '../../../index.js';

/**
 * F203-11 regression suite.
 *
 * FIPS 203 Algorithm 20 (ML-KEM.Encaps) separates two failure conditions that the SDK
 * previously collapsed into one:
 *
 *   1: m <- B^32
 *   2: if m == NULL then
 *   3:     return ⊥      ▷ return an error indication if random bit generation failed
 *   4: end if
 *
 * Input checking (§7.2) happens *before* the algorithm runs; RBG failure is a condition
 * *inside* it. Reporting an entropy outage as `INVALID_KEY` told the operator the
 * recipient's key was malformed when it was not, sending the investigation at key
 * distribution instead of at the host's entropy source.
 *
 * The X-Wing mapping to `INVALID_KEY` for degenerate X25519 points is deliberate and
 * load-bearing (commit cefdd68, #74). The last test here pins it, because the natural way
 * to get the RBG case wrong is to widen the new branch until it swallows that one too.
 */

/**
 * Runs `fn` and returns the `PqcError` code it threw, or a description of what else
 * happened. Asserting on the returned string beats `toThrowError(objectContaining(...))`
 * here: a wrong-but-thrown error reports its actual code in the diff, and it keeps the
 * assertion fully typed.
 */
const codeOfThrown = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    return error instanceof PqcError ? error.code : `non-PqcError: ${String(error)}`;
  }
  return 'no error thrown';
};

// `crypto` is a getter on globalThis in Node; stubGlobal handles the restore.
const breakEntropy = (mode: 'throw' | 'absent' | 'short'): void => {
  const real = globalThis.crypto;
  if (mode === 'absent') {
    vi.stubGlobal('crypto', {});
    return;
  }
  vi.stubGlobal('crypto', {
    ...real,
    subtle: real.subtle,
    getRandomValues:
      mode === 'throw'
        ? () => {
            throw new Error('entropy pool exhausted');
          }
        : // A host that returns a short buffer has equally failed to produce randomness;
          // this is the `m == NULL` branch in everything but name.
          (buf: Uint8Array) => buf.subarray(0, 0),
  });
};

describe('F203-11: RBG failure is reported as RBG_FAILURE, not INVALID_KEY', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each(['throw', 'absent', 'short'] as const)(
    'encapsulateTo surfaces RBG_FAILURE when the platform RBG %s',
    (mode) => {
      const spec = KEM_ALGORITHMS['ml-kem-768'];
      const { publicKey } = spec.kem.keygen();

      breakEntropy(mode);

      try {
        expect(() => encapsulateTo(spec, publicKey, 'ml-kem-768')).toThrow(PqcError);
        expect(codeOfThrown(() => encapsulateTo(spec, publicKey, 'ml-kem-768'))).toBe(
          'RBG_FAILURE',
        );
      } finally {
        vi.unstubAllGlobals();
      }
    },
  );

  it('reports RBG_FAILURE through the public pqc.encrypt entry point too', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-kem-768' });

    breakEntropy('throw');

    await expect(pqc.encrypt('secret', pair.publicKey)).rejects.toMatchObject({
      code: 'RBG_FAILURE',
    });
  });

  it('the RBG_FAILURE message leaks no key material, only the failure and a length', () => {
    const spec = KEM_ALGORITHMS['ml-kem-768'];
    const { publicKey } = spec.kem.keygen();

    breakEntropy('throw');

    try {
      encapsulateTo(spec, publicKey, 'ml-kem-768');
      expect.unreachable('encapsulation should have failed');
    } catch (error) {
      const message = (error as PqcError).message;
      expect(message).toContain('ml-kem-768');
      expect(message).not.toContain('entropy pool exhausted'); // no host error text
      expect(message).not.toMatch(/[0-9a-f]{32,}/i); // no hex-encoded material
    }
  });

  it('a valid key still encapsulates normally once the RBG works again', async () => {
    // Confirms the stubbing above is what caused the failures, not a broken fixture.
    const pair = await pqc.keys.generate({ algorithm: 'ml-kem-768' });
    const ciphertext = await pqc.encrypt('secret', pair.publicKey);

    await expect(pqc.decrypt(ciphertext, pair.secretKey)).resolves.toBeInstanceOf(Uint8Array);
  });
});

describe('F203-11 non-regression: the X-Wing degenerate-point mapping is unchanged', () => {
  // draft-connolly-cfrg-xwing-kem-10 pk = pk_M(1184) || pk_X(32). @noble/curves rejects the
  // small-order X25519 points because they drive the shared secret to all-zero. That must
  // keep surfacing as INVALID_KEY — it genuinely is a bad key, and the new RBG branch must
  // not capture it.
  const degenerate: Record<string, Uint8Array> = {
    zero: new Uint8Array(32),
    one: Uint8Array.from([1, ...new Array<number>(31).fill(0)]),
  };

  it.each(Object.entries(degenerate))(
    'encapsulateTo still maps a %s pk_X to INVALID_KEY',
    (_name, pkX) => {
      const spec = KEM_ALGORITHMS['x-wing'];
      const { publicKey } = spec.kem.keygen();
      const tampered = Uint8Array.from(publicKey);
      tampered.set(pkX, 1184);

      expect(codeOfThrown(() => encapsulateTo(spec, tampered, 'x-wing'))).toBe('INVALID_KEY');
    },
  );

  it('a wrong-length ML-KEM public key still maps to INVALID_KEY, not RBG_FAILURE', async () => {
    // The §7.2 type check must keep winning over the new branch.
    await expect(
      pqc.encrypt('x', {
        algorithm: 'ml-kem-768',
        use: 'public',
        bytes: new Uint8Array(10),
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });
});
