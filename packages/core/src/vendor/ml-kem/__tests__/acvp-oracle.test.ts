import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { KEM_ALGORITHMS } from '../../../algorithms.js';
import manifest from '../../../vectors/acvp/ml-kem/manifest.json';

const algorithms = {
  'ML-KEM-512': 'ml-kem-512',
  'ML-KEM-768': 'ml-kem-768',
  'ML-KEM-1024': 'ml-kem-1024',
} as const;
interface ReferenceCase {
  tcId: number;
  d?: string;
  z?: string;
  ek: string;
  dk: string;
  m?: string;
  c?: string;
  k?: string;
  testPassed?: boolean;
}
interface ReferenceGroup {
  tgId: number;
  parameterSet: keyof typeof algorithms;
  function?: string;
  tests: ReferenceCase[];
}
interface ReferenceFile {
  testGroups: ReferenceGroup[];
}
const bytes = (hex: string | undefined): Uint8Array => {
  if (hex === undefined) throw new Error('Missing reference field');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};
const datasets = manifest.files.map((file) => {
  const raw = readFileSync(new URL(`../../../vectors/acvp/ml-kem/${file.file}`, import.meta.url));
  return { file, raw, data: JSON.parse(raw.toString('utf8')) as ReferenceFile };
});

describe('Pinned official ML-KEM public samples', () => {
  it('preserves exact upstream bytes and the complete case inventory', () => {
    expect(manifest.commit).toBe('975de31eb83d87039ec88934fdc47d8c312b892d');
    let count = 0;
    for (const { file, raw, data } of datasets) {
      expect(createHash('sha256').update(raw).digest('hex')).toBe(file.sha256);
      expect(createHash('sha1').update(`blob ${raw.length}\0`).update(raw).digest('hex')).toBe(
        file.gitBlob,
      );
      expect(
        data.testGroups.map((g) => ({
          tgId: g.tgId,
          parameterSet: g.parameterSet,
          function: g.function ?? 'keyGen',
          tcIds: g.tests.map((t) => t.tcId),
        })),
      ).toEqual(file.groups);
      for (const group of data.testGroups) {
        expect(new Set(group.tests.map((t) => t.tcId)).size).toBe(group.tests.length);
        count += group.tests.length;
      }
    }
    expect(count).toBe(240);
    expect(manifest.totalCases).toBe(count);
  });

  for (const { data } of datasets) {
    for (const group of data.testGroups) {
      const operation = group.function ?? 'keyGen';
      const spec = KEM_ALGORITHMS[algorithms[group.parameterSet]];
      describe(`${group.parameterSet} ${operation}`, () => {
        it.each(group.tests)('official tcId $tcId', (reference) => {
          const kem = spec.kem;
          if (operation === 'keyGen') {
            const seed = new Uint8Array([...bytes(reference.d), ...bytes(reference.z)]);
            const before = seed.slice();
            const pair = kem.keygen(seed);
            expect(pair.publicKey).toEqual(bytes(reference.ek));
            expect(pair.secretKey).toEqual(bytes(reference.dk));
            expect(seed).toEqual(before);
          } else if (operation === 'encapsulation') {
            const ek = bytes(reference.ek),
              m = bytes(reference.m);
            const ekBefore = ek.slice(),
              mBefore = m.slice();
            const out = kem.encapsulate(ek, m);
            // Both produced values are compared directly; a decrypt-only check is insufficient.
            expect(out.cipherText).toEqual(bytes(reference.c));
            expect(out.sharedSecret).toEqual(bytes(reference.k));
            expect(kem.decapsulate(out.cipherText, bytes(reference.dk))).toEqual(
              bytes(reference.k),
            );
            expect(ek).toEqual(ekBefore);
            expect(m).toEqual(mBefore);
          } else if (operation === 'decapsulation') {
            expect(kem.decapsulate(bytes(reference.c), bytes(reference.dk))).toEqual(
              bytes(reference.k),
            );
          } else if (operation === 'encapsulationKeyCheck') {
            const run = () => kem.encapsulate(bytes(reference.ek), new Uint8Array(32));
            if (reference.testPassed) expect(run).not.toThrow();
            else expect(run).toThrow();
          } else if (operation === 'decapsulationKeyCheck') {
            const run = () =>
              kem.decapsulate(new Uint8Array(spec.ciphertextLength), bytes(reference.dk));
            if (reference.testPassed) expect(run).not.toThrow();
            else expect(run).toThrow();
          } else {
            throw new Error(`Unhandled reference operation: ${operation}`);
          }
        });
      });
    }
  }
});
