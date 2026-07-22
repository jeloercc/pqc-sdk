import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { SUPPORTED_ALGORITHMS, pqc, version } from './index.js';

describe('@pqc-sdk/core', () => {
  it('exposes the package.json version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version: string;
    };
    expect(version).toBe(pkg.version);
  });

  it('lists the implemented algorithms', () => {
    expect(SUPPORTED_ALGORITHMS).toEqual(['ml-kem-768', 'ml-dsa-65', 'x-wing']);
  });

  it('exposes the full public API', () => {
    expect(typeof pqc.keys.generate).toBe('function');
    expect(typeof pqc.keys.serialize).toBe('function');
    expect(typeof pqc.keys.deserialize).toBe('function');
    expect(typeof pqc.encrypt).toBe('function');
    expect(typeof pqc.decrypt).toBe('function');
    expect(typeof pqc.sign).toBe('function');
    expect(typeof pqc.verify).toBe('function');
  });
});
