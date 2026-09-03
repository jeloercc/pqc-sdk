import { describe, expect, it } from 'vitest';

import { generate } from './keys.js';
import { decryptStream, encryptStream } from './stream.js';
import { collect, single } from './stream-test-helpers.js';
import { decryptWebStream, encryptWebStream } from './stream-web.js';
import type { KemAlgorithm } from './types.js';

/**
 * Day 3 of the streaming-encryption sprint
 * (docs/proposals/streaming-encryption.md): the Web Streams adapters are
 * thin plumbing around encryptStream/decryptStream (no independent crypto
 * logic — that's already covered by stream.test.ts and
 * stream-mutations.test.ts), so this file only needs to prove the bridging
 * itself works: piping through both adapters round-trips, and a tampered
 * pipe still fails closed the same way the core primitive does.
 */

const ALGORITHMS: readonly KemAlgorithm[] = ['ml-kem-768', 'x-wing'];

async function toArray(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    parts.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function fromBytes(data: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });
}

describe.each(ALGORITHMS)('encryptWebStream/decryptWebStream (%s)', (algorithm) => {
  it('round-trips through pipeThrough end to end', async () => {
    const pair = await generate({ algorithm });
    const plaintext = new TextEncoder().encode('data piped through a TransformStream');

    const ciphertext = await toArray(
      fromBytes(plaintext).pipeThrough(encryptWebStream(pair.publicKey, { chunkSize: 8 })),
    );
    const decrypted = await toArray(
      fromBytes(ciphertext).pipeThrough(decryptWebStream(pair.secretKey)),
    );

    expect(new TextDecoder().decode(decrypted)).toBe('data piped through a TransformStream');
  });

  it('propagates a tampered ciphertext as a pipeline rejection, not silent success', async () => {
    const pair = await generate({ algorithm });
    const plaintext = new TextEncoder().encode('to be tampered with');
    const ciphertext = await toArray(
      fromBytes(plaintext).pipeThrough(encryptWebStream(pair.publicKey, { chunkSize: 8 })),
    );
    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff; // flip a byte in the final chunk's tag

    await expect(
      toArray(fromBytes(tampered).pipeThrough(decryptWebStream(pair.secretKey))),
    ).rejects.toMatchObject({ code: 'DECRYPTION_FAILED' });
  });

  it('interoperates with the core primitive: web-stream-encrypted decrypts via decryptStream and vice versa', async () => {
    const pair = await generate({ algorithm });
    const plaintext = new TextEncoder().encode('cross-check against the core primitive');

    const viaWebStream = await toArray(
      fromBytes(plaintext).pipeThrough(encryptWebStream(pair.publicKey, { chunkSize: 8 })),
    );
    const decryptedByCore = await collect(decryptStream(pair.secretKey, single(viaWebStream)));
    expect(new TextDecoder().decode(decryptedByCore)).toBe(
      'cross-check against the core primitive',
    );

    const viaCore = await collect(
      encryptStream(pair.publicKey, single(plaintext), { chunkSize: 8 }),
    );
    const decryptedByWebStream = await toArray(
      fromBytes(viaCore).pipeThrough(decryptWebStream(pair.secretKey)),
    );
    expect(new TextDecoder().decode(decryptedByWebStream)).toBe(
      'cross-check against the core primitive',
    );
  });
});
