import { bench, describe } from 'vitest';

import { pqc } from './index.js';
import { generateKeyPairFromSeed } from './keys.js';

// eslint-disable-next-line @typescript-eslint/require-await -- see stream-test-helpers.ts.
async function* singleChunk(data: Uint8Array): AsyncGenerator<Uint8Array> {
  yield data;
}

async function drain(chunks: AsyncIterable<Uint8Array>): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for await (const _chunk of chunks) {
    // Throughput benchmark: only draining matters, not the bytes themselves.
  }
}

// Fixed seeds and patterned payloads keep every run measuring the same work.
// Only the keygen benches use the real RNG — there, the RNG *is* the operation.
const KEM_SEED = new Uint8Array(64).map((_, i) => (i * 7 + 1) % 256);
const DSA_SEED = new Uint8Array(32).map((_, i) => (i * 11 + 3) % 256);
const XWING_SEED = new Uint8Array(32).map((_, i) => (i * 13 + 5) % 256);
const payload = (bytes: number) => new Uint8Array(bytes).map((_, i) => i % 251);

const PAYLOAD_1KIB = payload(1024);
const PAYLOAD_100KIB = payload(100 * 1024);
const PAYLOAD_1MIB = payload(1024 * 1024);

const kemPair = generateKeyPairFromSeed('ml-kem-768', KEM_SEED);
const dsaPair = generateKeyPairFromSeed('ml-dsa-65', DSA_SEED);
const xwingPair = generateKeyPairFromSeed('x-wing', XWING_SEED);
const ct1KiB = await pqc.encrypt(PAYLOAD_1KIB, kemPair.publicKey);
const ct100KiB = await pqc.encrypt(PAYLOAD_100KIB, kemPair.publicKey);
const xwingCt1KiB = await pqc.encrypt(PAYLOAD_1KIB, xwingPair.publicKey);
const xwingCt100KiB = await pqc.encrypt(PAYLOAD_100KIB, xwingPair.publicKey);
const sig1KiB = await pqc.sign(PAYLOAD_1KIB, dsaPair.secretKey);

// Streaming ciphertexts (default 64 KiB chunk size, ~16 chunks at 1 MiB) —
// collected once, same "prepare once, bench the operation" pattern as the
// one-shot ciphertexts above.
async function collectStream(chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of chunks) {
    parts.push(chunk);
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
const streamCt1MiB = await collectStream(
  pqc.encryptStream(kemPair.publicKey, singleChunk(PAYLOAD_1MIB)),
);
const xwingStreamCt1MiB = await collectStream(
  pqc.encryptStream(xwingPair.publicKey, singleChunk(PAYLOAD_1MIB)),
);

// ~200 ms warmup lets the JIT settle; ~1.5 s sampling keeps the mean stable
// even for the slowest operation (ML-DSA sign, ~tens of ms per op).
const OPTS = { warmupTime: 200, time: 1500 } as const;

describe('ml-kem-768', () => {
  bench(
    'keygen',
    async () => {
      // Pinned: since 0.8.0 the no-argument default is x-wing, so calling
      // generate() here would silently benchmark the hybrid instead of the
      // pure KEM this describe block is named for.
      await pqc.keys.generate({ algorithm: 'ml-kem-768' });
    },
    OPTS,
  );

  bench(
    'encrypt 1KiB',
    async () => {
      await pqc.encrypt(PAYLOAD_1KIB, kemPair.publicKey);
    },
    OPTS,
  );

  bench(
    'encrypt 100KiB',
    async () => {
      await pqc.encrypt(PAYLOAD_100KIB, kemPair.publicKey);
    },
    OPTS,
  );

  bench(
    'decrypt 1KiB',
    async () => {
      await pqc.decrypt(ct1KiB, kemPair.secretKey);
    },
    OPTS,
  );

  bench(
    'decrypt 100KiB',
    async () => {
      await pqc.decrypt(ct100KiB, kemPair.secretKey);
    },
    OPTS,
  );
});

describe('x-wing', () => {
  bench(
    'keygen',
    async () => {
      await pqc.keys.generate({ algorithm: 'x-wing' });
    },
    OPTS,
  );

  bench(
    'encrypt 1KiB',
    async () => {
      await pqc.encrypt(PAYLOAD_1KIB, xwingPair.publicKey);
    },
    OPTS,
  );

  bench(
    'encrypt 100KiB',
    async () => {
      await pqc.encrypt(PAYLOAD_100KIB, xwingPair.publicKey);
    },
    OPTS,
  );

  bench(
    'decrypt 1KiB',
    async () => {
      await pqc.decrypt(xwingCt1KiB, xwingPair.secretKey);
    },
    OPTS,
  );

  bench(
    'decrypt 100KiB',
    async () => {
      await pqc.decrypt(xwingCt100KiB, xwingPair.secretKey);
    },
    OPTS,
  );
});

describe('ml-dsa-65', () => {
  bench(
    'keygen',
    async () => {
      await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    },
    OPTS,
  );

  bench(
    'sign 1KiB',
    async () => {
      await pqc.sign(PAYLOAD_1KIB, dsaPair.secretKey);
    },
    OPTS,
  );

  bench(
    'verify 1KiB',
    async () => {
      await pqc.verify(PAYLOAD_1KIB, sig1KiB, dsaPair.publicKey);
    },
    OPTS,
  );
});

describe('ml-kem-768 streaming', () => {
  bench(
    'encryptStream 1MiB (default 64KiB chunks)',
    async () => {
      await collectStream(pqc.encryptStream(kemPair.publicKey, singleChunk(PAYLOAD_1MIB)));
    },
    OPTS,
  );

  bench(
    'decryptStream 1MiB (default 64KiB chunks)',
    async () => {
      await drain(pqc.decryptStream(kemPair.secretKey, singleChunk(streamCt1MiB)));
    },
    OPTS,
  );
});

describe('x-wing streaming', () => {
  bench(
    'encryptStream 1MiB (default 64KiB chunks)',
    async () => {
      await collectStream(pqc.encryptStream(xwingPair.publicKey, singleChunk(PAYLOAD_1MIB)));
    },
    OPTS,
  );

  bench(
    'decryptStream 1MiB (default 64KiB chunks)',
    async () => {
      await drain(pqc.decryptStream(xwingPair.secretKey, singleChunk(xwingStreamCt1MiB)));
    },
    OPTS,
  );
});
