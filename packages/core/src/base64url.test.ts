import { describe, expect, it } from 'vitest';

import { fromBase64Url, toBase64Url } from './base64url.js';

describe('base64url', () => {
  it('roundtrips arbitrary byte sequences', () => {
    const inputs = [
      new Uint8Array(0),
      new Uint8Array([0]),
      new Uint8Array([255]),
      new Uint8Array([0, 1, 2]),
      new Uint8Array([0, 1, 2, 3]),
      Uint8Array.from({ length: 256 }, (_, i) => i),
    ];

    for (const input of inputs) {
      const decoded = fromBase64Url(toBase64Url(input));
      expect(Buffer.from(decoded).equals(Buffer.from(input))).toBe(true);
    }
  });

  it('rejects strings of an impossible length (length % 4 === 1)', () => {
    // A single base64url character cannot encode any whole byte.
    expect(() => fromBase64Url('A')).toThrow(/impossible length/i);
    expect(() => fromBase64Url('AAAAA')).toThrow(/impossible length/i);
  });

  it('rejects non-canonical encodings whose trailing bits are not zero', () => {
    // "AB" decodes the single byte 0x00, but the 4 trailing bits of 'B' (value 1)
    // are non-zero, so it is not the canonical encoding of any byte sequence.
    // The canonical form is "AA".
    expect(toBase64Url(new Uint8Array([0]))).toBe('AA');
    expect(() => fromBase64Url('AB')).toThrow(TypeError);
  });
});
