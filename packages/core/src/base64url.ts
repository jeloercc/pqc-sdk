const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const CHAR_TO_VALUE = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));

/** Codifica bytes a base64url sin padding. Implementación pura, sin Buffer/btoa. */
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

/** Decodifica base64url sin padding. Lanza TypeError ante caracteres inválidos. */
export function fromBase64Url(encoded: string): Uint8Array {
  if (encoded.length % 4 === 1) {
    throw new TypeError('base64url inválido: longitud imposible');
  }
  const out = new Uint8Array(Math.floor((encoded.length * 3) / 4));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (const char of encoded) {
    const value = CHAR_TO_VALUE.get(char);
    if (value === undefined) {
      throw new TypeError(`base64url inválido: carácter ${JSON.stringify(char)}`);
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}
