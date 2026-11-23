import { describe, expect, it } from 'vitest';

import { ml_kem512, ml_kem768, ml_kem1024 } from '../ml-kem.js';

// Expected lengths/offsets come from the parameter-set layouts, not PARAMS under test.
const sets = [
  { name: '512', k: 2, pk: 800, sk: 1632, ct: 768, hash: 1568, kem: ml_kem512 },
  { name: '768', k: 3, pk: 1184, sk: 2400, ct: 1088, hash: 2336, kem: ml_kem768 },
  { name: '1024', k: 4, pk: 1568, sk: 3168, ct: 1568, hash: 3104, kem: ml_kem1024 },
] as const;

for (const set of sets) {
  describe(`ML-KEM-${set.name} parameter boundaries`, () => {
    const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
    const pair = set.kem.keygen(seed);
    const msg = new Uint8Array(32).fill(19);
    const encapsulated = set.kem.encapsulate(pair.publicKey, msg);

    for (const kind of ['pk', 'sk', 'ct'] as const) {
      it.each([-1, 1])(`rejects ${kind} length offset %s without changing input`, (delta) => {
        const original =
          kind === 'pk' ? pair.publicKey : kind === 'sk' ? pair.secretKey : encapsulated.cipherText;
        expect(original.length).toBe(set[kind]);
        const bad = new Uint8Array(original.length + delta);
        bad.set(original.subarray(0, bad.length));
        const before = bad.slice();
        const run = () =>
          kind === 'pk'
            ? set.kem.encapsulate(bad, msg)
            : kind === 'sk'
              ? set.kem.decapsulate(encapsulated.cipherText, bad)
              : set.kem.decapsulate(bad, pair.secretKey);
        expect(run).toThrow();
        expect(bad).toEqual(before);
      });
    }

    it.each([0, 256 * set.k - 1])('rejects coefficient q at position %s', (position) => {
      const bad = pair.publicKey.slice(),
        before = pair.publicKey.slice();
      const offset = Math.floor((position * 12) / 8),
        shift = position % 2 === 0 ? 0 : 4;
      const word = (bad[offset] as number) | ((bad[offset + 1] as number) << 8);
      const changed = (word & ~(0xfff << shift)) | (3329 << shift);
      bad[offset] = changed & 0xff;
      bad[offset + 1] = (changed >> 8) & 0xff;
      const invalidBefore = bad.slice();
      expect(() => set.kem.encapsulate(bad, msg)).toThrow(/modulus/);
      expect(() => set.kem.prepare(bad)).toThrow(/modulus/);
      expect(bad).toEqual(invalidBefore);
      expect(pair.publicKey).toEqual(before);
      expect(set.kem.decapsulate(encapsulated.cipherText, pair.secretKey)).toEqual(
        encapsulated.sharedSecret,
      );
    });

    it('checks the stored hash at the parameter-specific offset', () => {
      const bad = pair.secretKey.slice();
      bad[set.hash] = (bad[set.hash] as number) ^ 1;
      const before = bad.slice(),
        prepared = set.kem.prepare(pair.publicKey);
      try {
        expect(() => set.kem.decapsulate(encapsulated.cipherText, bad)).toThrow(/hash/);
        expect(() => prepared.decapsulate(encapsulated.cipherText, bad)).toThrow(/match/);
        expect(bad).toEqual(before);
      } finally {
        prepared.clean();
      }
    });

    it('rejects a valid secret key bound to a different prepared public key', () => {
      const other = set.kem.keygen(new Uint8Array(64).fill(91));
      const prepared = set.kem.prepare(other.publicKey);
      const before = pair.secretKey.slice();
      try {
        expect(() => prepared.decapsulate(encapsulated.cipherText, pair.secretKey)).toThrow(
          /match/,
        );
        expect(pair.secretKey).toEqual(before);
      } finally {
        prepared.clean();
      }
    });
  });
}
