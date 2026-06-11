import { describe, expect, it } from 'vitest';

import { SUPPORTED_ALGORITHMS, pqc, version } from './index.js';

describe('@pqc-sdk/core', () => {
  it('expone la versión del SDK', () => {
    expect(version).toBe('0.0.1');
  });

  it('lista los algoritmos implementados', () => {
    expect(SUPPORTED_ALGORITHMS).toEqual(['ml-kem-768', 'ml-dsa-65']);
  });

  it('expone la API pública completa', () => {
    expect(typeof pqc.keys.generate).toBe('function');
    expect(typeof pqc.keys.serialize).toBe('function');
    expect(typeof pqc.keys.deserialize).toBe('function');
    expect(typeof pqc.encrypt).toBe('function');
    expect(typeof pqc.decrypt).toBe('function');
    expect(typeof pqc.sign).toBe('function');
    expect(typeof pqc.verify).toBe('function');
  });
});
