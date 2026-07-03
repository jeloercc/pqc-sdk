import { bench, describe } from 'vitest';

import { pqc } from './index.js';
import { generateKeyPairFromSeed } from './keys.js';

// Fixed seeds and patterned payloads keep every run measuring the same work.
// Only the keygen benches use the real RNG — there, the RNG *is* the operation.
const KEM_SEED = new Uint8Array(64).map((_, i) => (i * 7 + 1) % 256);
const DSA_SEED = new Uint8Array(32).map((_, i) => (i * 11 + 3) % 256);
const payload = (bytes: number) => new Uint8Array(bytes).map((_, i) => i % 251);

const PAYLOAD_1KIB = payload(1024);
const PAYLOAD_100KIB = payload(100 * 1024);

const kemPair = generateKeyPairFromSeed('ml-kem-768', KEM_SEED);
const dsaPair = generateKeyPairFromSeed('ml-dsa-65', DSA_SEED);
const ct1KiB = await pqc.encrypt(PAYLOAD_1KIB, kemPair.publicKey);
const ct100KiB = await pqc.encrypt(PAYLOAD_100KIB, kemPair.publicKey);
const sig1KiB = await pqc.sign(PAYLOAD_1KIB, dsaPair.secretKey);

// ~200 ms warmup lets the JIT settle; ~1.5 s sampling keeps the mean stable
// even for the slowest operation (ML-DSA sign, ~tens of ms per op).
const OPTS = { warmupTime: 200, time: 1500 } as const;

describe('ml-kem-768', () => {
  bench(
    'keygen',
    async () => {
      await pqc.keys.generate();
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
