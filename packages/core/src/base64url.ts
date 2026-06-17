const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const CHAR_TO_VALUE = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));

/** Encodes bytes to unpadded base64url. Pure implementation, no Buffer/btoa. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += ALPHABET[b0 >> 2]!;
    out += ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)]!;
    if (b1 !== undefined) out += ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)]!;
    if (b2 !== undefined) out += ALPHABET[b2 & 0x3f]!;
  }
  return out;
}

/** Decodes unpadded base64url. Throws TypeError on invalid characters. */
export function fromBase64Url(encoded: string): Uint8Array {
  if (encoded.length % 4 === 1) {
    throw new TypeError('Invalid base64url: impossible length');
  }
  const out = new Uint8Array(Math.floor((encoded.length * 3) / 4));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (const char of encoded) {
    const value = CHAR_TO_VALUE.get(char);
    if (value === undefined) {
      throw new TypeError(`Invalid base64url: character ${JSON.stringify(char)}`);
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex++] = (buffer >> bits) & 0xff;
    }
  }
  // Reject non-canonical input: the leftover bits of the final group (those that
  // do not complete a byte) must be zero, otherwise the string is not the
  // canonical encoding of any byte sequence.
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new TypeError('Invalid base64url: non-canonical trailing bits');
  }
  return out;
}
