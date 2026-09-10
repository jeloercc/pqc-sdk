import { describe, expect, it } from 'vitest';

import { ml_dsa65 } from '../ml-dsa.js';

/**
 * F204-10 regression suite — zeroization on the verification path.
 *
 * FIPS 204 §3.6.3: "The data used internally by verification algorithms is similarly
 * sensitive for some applications, including the verification of signatures that are used
 * as bearer tokens (i.e., authentication secrets) or the verification of signatures on
 * plaintext messages that are intended to be confidential. … Therefore, implementations of
 * ML-DSA shall ensure that any potentially sensitive intermediate data is destroyed as
 * soon as it is no longer needed."
 *
 * Upstream 0.7.1 had no `cleanBytes` call anywhere in `internal.verify` — all 14 in the
 * file were in key generation and signing.
 *
 * What these tests can and cannot establish:
 *
 *   - They CAN establish that the change is output-inert on every path, that the caller's
 *     inputs are not collaterally wiped (the real hazard, since `splitCoder.decode`
 *     returns subarray *views* into them), and that the zeroization is in the source on
 *     every exit rather than only the success path.
 *   - They CANNOT observe heap state after the call returns. JavaScript exposes no way to
 *     assert that a buffer the implementation dropped was zeroed first, and a moving
 *     garbage collector may have relocated it regardless. No test here pretends otherwise.
 */

interface MlDsaSurface {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean;
}

const dsa = ml_dsa65 as unknown as MlDsaSurface;
const utf8 = new TextEncoder();

/** Copy with one byte flipped. `as number` matches the repo idiom for noUncheckedIndexedAccess. */
function tamper(bytes: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy[index] = (copy[index] as number) ^ mask;
  return copy;
}

describe('F204-10: verify remains output-inert after adding zeroization', () => {
  it('still accepts a genuine signature', () => {
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('important document');

    expect(dsa.verify(dsa.sign(msg, secretKey), msg, publicKey)).toBe(true);
  });

  it('still rejects on each early-exit path without throwing', () => {
    // Every one of these leaves `verify` through a different `return false`, which is the
    // point: the try/finally has to fire on all of them, and none may start throwing.
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('msg');
    const sig = dsa.sign(msg, secretKey);

    const cases: Array<[string, () => boolean]> = [
      ['signature too short', () => dsa.verify(new Uint8Array(3), msg, publicKey)],
      ['signature too long', () => dsa.verify(new Uint8Array(3310), msg, publicKey)],
      ['all-0xff signature', () => dsa.verify(new Uint8Array(3309).fill(0xff), msg, publicKey)],
      ['all-zero signature', () => dsa.verify(new Uint8Array(3309), msg, publicKey)],
      ['tampered c-tilde region', () => dsa.verify(tamper(sig, 0), msg, publicKey)],
      ['tampered z region', () => dsa.verify(tamper(sig, 1000, 0xff), msg, publicKey)],
      ['tampered hint region', () => dsa.verify(tamper(sig, 3300, 0xff), msg, publicKey)],
      ['altered message', () => dsa.verify(sig, utf8.encode('other'), publicKey)],
      ['other key pair', () => dsa.verify(sig, msg, dsa.keygen().publicKey)],
    ];

    for (const [name, run] of cases) {
      expect(run(), name).toBe(false);
    }
  });
});

describe('F204-10: zeroization does not reach caller-owned memory', () => {
  // The hazard this guards. `splitCoder.decode` returns subarray *views* into its input for
  // numeric segments — `rho` into the public key, `cTilde` into the signature — and fresh
  // objects only for coder segments. Wiping the wrong one silently destroys the caller's
  // key or signature. This is the ML-DSA analogue of the equivalent ML-KEM check.

  it('leaves the public key byte-identical after verification', () => {
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('msg');
    const sig = dsa.sign(msg, secretKey);
    const before = Uint8Array.from(publicKey);

    dsa.verify(sig, msg, publicKey);

    expect(Buffer.from(publicKey).equals(Buffer.from(before))).toBe(true);
    expect(publicKey.some((b) => b !== 0)).toBe(true);
  });

  it('leaves the signature byte-identical after verification', () => {
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('msg');
    const sig = dsa.sign(msg, secretKey);
    const before = Uint8Array.from(sig);

    dsa.verify(sig, msg, publicKey);

    expect(Buffer.from(sig).equals(Buffer.from(before))).toBe(true);
  });

  it('leaves the message byte-identical after verification', () => {
    // `mu` aliases `msg` in external-mu mode, so the implementation must not wipe it. This
    // pins the non-external path too, where mu is a fresh digest and msg must still survive.
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('a message that must survive verification');
    const sig = dsa.sign(msg, secretKey);
    const before = Uint8Array.from(msg);

    dsa.verify(sig, msg, publicKey);

    expect(Buffer.from(msg).equals(Buffer.from(before))).toBe(true);
  });

  it('a key and signature stay reusable across repeated verifications', () => {
    // The end-to-end consequence of the three checks above: if any caller-owned buffer were
    // being wiped, the second call would fail.
    const { publicKey, secretKey } = dsa.keygen();
    const msg = utf8.encode('msg');
    const sig = dsa.sign(msg, secretKey);

    for (let i = 0; i < 3; i++) {
      expect(dsa.verify(sig, msg, publicKey)).toBe(true);
    }
  });
});

describe('F204-10: the zeroization is on every exit path in the source', () => {
  it('verify wraps its body in try/finally and wipes the fresh intermediates', async () => {
    // No behavioural test can see whether a dropped buffer was zeroed first, so the
    // structure is asserted on the source instead. A future edit that removes the finally,
    // or that starts wiping a caller-owned view, fails here.
    const { readFileSync } = await import('node:fs');
    const file = readFileSync(new URL('../ml-dsa.ts', import.meta.url), 'utf8');

    const start = file.indexOf('    verify: (\n      sig:');
    expect(start).toBeGreaterThan(-1);
    const body = file.slice(start, file.indexOf('\n    },', start));

    expect(body).toContain('try {');
    expect(body).toContain('} finally {');

    // The fresh intermediates that must be wiped.
    for (const name of ['t1', 'tr', 'mu', 'z', 'h', 'c', 'zNtt', 'c2', 'wTick1']) {
      expect(body, `expected ${name} to be zeroized`).toContain(`cleanBytes(${name})`);
    }

    // `mu` is only wiped when it is a fresh digest, never when it aliases `msg`.
    expect(body).toContain('if (ownMu && mu !== undefined) cleanBytes(mu)');

    // The caller-owned views must never be passed to cleanBytes.
    expect(body).not.toMatch(/cleanBytes\([^)]*\brho\b/);
    expect(body).not.toMatch(/cleanBytes\([^)]*\bcTilde\b/);
    expect(body).not.toMatch(/cleanBytes\([^)]*\bpublicKey\b/);
    expect(body).not.toMatch(/cleanBytes\([^)]*\bsig\b/);
  });
});
