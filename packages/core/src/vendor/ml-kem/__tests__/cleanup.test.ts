import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { __tests } from '../ml-kem.js';

interface Observation {
  records: { observed: number; uncleared: number }[];
  failures: unknown[];
  controlErrors: unknown[];
  hooksRestored: boolean;
  uninstrumentedControls: number;
}
const observer = fileURLToPath(
  new URL('../../../../scripts/cleanup-observer.mjs', import.meta.url),
);

describe('ML-KEM owned intermediate cleanup', () => {
  it.each(['sampling', 'outer', 'polynomial'])(
    '%s buffers clear on normal and exceptional exits',
    (mode) => {
      const child = spawnSync(process.execPath, ['--import', 'tsx', observer, mode], {
        encoding: 'utf8',
        timeout: 90_000,
        maxBuffer: 4 * 1024 * 1024,
      });
      expect(child.error, child.stderr).toBeUndefined();
      expect(child.status, child.stderr).toBe(0);
      const result = JSON.parse(child.stdout) as Observation;
      expect(result.controlErrors).toEqual([]);
      expect(result.records.length).toBeGreaterThan(0);
      expect(result.hooksRestored).toBe(true);
      expect(result.uninstrumentedControls).toBe(result.records.length);
      expect(result.failures, JSON.stringify(result.failures)).toEqual([]);
    },
    100_000,
  );

  it.each([2, 3])('does not erase borrowed SamplePolyCBD input for eta=%s', (eta) => {
    const input = Uint8Array.from({ length: 64 * eta }, (_, i) => i & 0xff);
    const before = input.slice();
    const sampler = __tests as { SamplePolyCBD: (bytes: Uint8Array, eta: number) => Uint16Array };
    expect(sampler.SamplePolyCBD(input, eta)).toHaveLength(256);
    expect(input).toEqual(before);
  });
});
