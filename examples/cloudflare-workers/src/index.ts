import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on Cloudflare Workers';

// Streaming (pqcenc.v2 chunked envelope, docs/proposals/streaming-encryption.md):
// no filesystem in workerd, so this builds a large in-memory synthetic
// payload and pipes it through TransformStreams end to end — proving
// pqc.encryptWebStream/decryptWebStream work on workerd's native Streams
// implementation, the same property fs-based streaming relies on elsewhere.
const LARGE_PAYLOAD_BYTES = 4 * 1024 * 1024; // 4 MiB — Workers CPU-time budget
// keeps this smaller than the Node/Deno examples' 8 MiB.

function randomPayload(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  const RANDOM_CHUNK = 65536; // crypto.getRandomValues' per-call cap
  for (let offset = 0; offset < bytes.length; offset += RANDOM_CHUNK) {
    crypto.getRandomValues(bytes.subarray(offset, offset + RANDOM_CHUNK));
  }
  return bytes;
}

function toReadableStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

async function streamingRoundtrip(algorithm: 'ml-kem-768' | 'x-wing') {
  const streamPair = await pqc.keys.generate({ algorithm });
  const plaintext = randomPayload(LARGE_PAYLOAD_BYTES);

  const ciphertext = await collect(
    toReadableStream(plaintext).pipeThrough(pqc.encryptWebStream(streamPair.publicKey)),
  );
  const decrypted = await collect(
    toReadableStream(ciphertext).pipeThrough(pqc.decryptWebStream(streamPair.secretKey)),
  );

  return {
    algorithm,
    plaintextBytes: plaintext.length,
    ciphertextBytes: ciphertext.length,
    byteForByteMatch: bytesEqual(plaintext, decrypted),
  };
}

export default {
  async fetch(): Promise<Response> {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt(message, pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
    const decoded = new TextDecoder().decode(plaintext);

    // Hybrid KEM (X25519 + ML-KEM-768, pqcenc.v2): same API, an x-wing key pair.
    const hybridPair = await pqc.keys.generate({ algorithm: 'x-wing' });
    const hybridCiphertext = await pqc.encrypt(message, hybridPair.publicKey);
    const hybridPlaintext = await pqc.decrypt(hybridCiphertext, hybridPair.secretKey);
    const hybridDecoded = new TextDecoder().decode(hybridPlaintext);

    const streaming = await streamingRoundtrip('ml-kem-768');
    const hybridStreaming = await streamingRoundtrip('x-wing');

    return Response.json({
      ok: decoded === message,
      algorithm: pair.algorithm,
      ciphertextBytes: ciphertext.length,
      roundtrip: decoded,
      hybrid: {
        ok: hybridDecoded === message,
        algorithm: hybridPair.algorithm,
        ciphertextBytes: hybridCiphertext.length,
        roundtrip: hybridDecoded,
      },
      streaming,
      hybridStreaming,
    });
  },
};
