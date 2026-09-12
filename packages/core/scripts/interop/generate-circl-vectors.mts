#!/usr/bin/env -S pnpm exec tsx
/**
 * Generates the CIRCL interop cross-check vectors under
 * src/vectors/interop/{circl-mldsa,circl-xwing,circl-mlkem768}.json.
 *
 * These are NOT ACVP vectors. ACVP proves this SDK's primitives match NIST's
 * own published expected output; it says nothing about whether a second,
 * independently-authored codebase agrees. This script performs the actual
 * cross-implementation check — this SDK vs. Cloudflare's CIRCL (Go) — ONCE,
 * locally, and commits the result. See docs/serialization-format.md (the
 * paragraph on what this format does and doesn't make interoperable) for why
 * this is scoped to raw primitive bytes only, never the SDK's own
 * pqcv1/pqcenc framing — nothing else implements that framing.
 *
 * Go and CIRCL are build-time-only tools for this script. They never run in
 * CI: CI only re-checks the committed JSON against this SDK's own code
 * (self-consistency / regression guard). The cross-implementation claim
 * itself — "CIRCL accepted this" / "CIRCL produced this and the SDK accepted
 * it" — is established once, here, and recorded with exact reproduction
 * instructions in each file's `meta` block.
 *
 * If ANY cross-check fails, this script exits non-zero and writes nothing.
 * A mismatch between this SDK and CIRCL is a finding to report, not
 * something to patch around by adjusting the check.
 *
 * Prerequisites:
 *   - `pnpm --filter @pqc-sdk/core build` (this script imports the built
 *     package for the public pqc.sign/pqc.verify calls, exactly like
 *     generate-golden-vectors.mjs)
 *   - Go toolchain, and the helper built once:
 *     `cd scripts/interop/circl-helper && go build -o circl-helper .`
 *   - This script imports .ts source directly (algorithms.ts's internals
 *     aren't part of the public dist), so it runs under `tsx`, not plain
 *     `node` — plain node's native type-stripping doesn't resolve the `.js`
 *     specifiers this repo's TS source uses for sibling `.ts` files.
 *
 * Usage (from packages/core): pnpm exec tsx scripts/interop/generate-circl-vectors.mts
 */

import { execFileSync } from 'node:child_process';
import console from 'node:console';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { pqc, version } from '@pqc-sdk/core';

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../../src/vendor/ml-dsa/ml-dsa.ts';
import { ml_kem768 } from '../../src/vendor/ml-kem/ml-kem.ts';
import { ml_kem768_x25519 } from '../../src/x-wing.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPER_BIN = join(HERE, 'circl-helper', 'circl-helper');
const VECTORS_DIR = join(HERE, '../../src/vectors/interop');

const REGENERATE_COMMAND =
  'cd packages/core && pnpm build && ' +
  '(cd scripts/interop/circl-helper && go build -o circl-helper .) && ' +
  'pnpm exec tsx scripts/interop/generate-circl-vectors.mts';

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}
function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
function hexEqual(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

if (!existsSync(HELPER_BIN)) {
  console.error(
    `generate-circl-vectors: ${HELPER_BIN} not found. Build it first:\n` +
      '  cd scripts/interop/circl-helper && go build -o circl-helper .',
  );
  process.exit(1);
}

function fail(label: string, detail: Record<string, unknown>): never {
  console.error(`generate-circl-vectors: CROSS-CHECK FAILED — ${label}`);
  console.error(JSON.stringify(detail, null, 2));
  console.error(
    'This is a finding, not a test bug. Nothing was written. Do not adjust this ' +
      'script to make the mismatch disappear — report it.',
  );
  process.exit(1);
}

interface CirclMldsaRequest {
  set: '44' | '65' | '87';
  pkHex: string;
  skHex: string;
  msgHex: string;
  sdkSigHex: string;
}
interface CirclKemRequest {
  pkHex: string;
  skHex: string;
  sdkCtHex: string;
}
interface CirclResponse {
  circlVersion: string;
  mldsa: Array<{
    set: string;
    circlVerifiesSdkSig: boolean;
    circlSigHex: string;
    circlVerifiesOwnSig: boolean;
  }>;
  mlkem?: { circlDecapsOfSdkCtSsHex: string; circlCtHex: string; circlSsHex: string };
  xwing?: { circlDecapsOfSdkCtSsHex: string; circlCtHex: string; circlSsHex: string };
}

function callCircl(request: {
  mldsa?: CirclMldsaRequest[];
  mlkem?: CirclKemRequest;
  xwing?: CirclKemRequest;
}): CirclResponse {
  const out = execFileSync(HELPER_BIN, [], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out) as CirclResponse;
}

// ---------------------------------------------------------------------------
// Priority 1: ML-DSA-44/65/87 signature generation, both directions.
// ---------------------------------------------------------------------------

const MLDSA_SETS = [
  { set: '44' as const, signer: ml_dsa44, message: 'circl interop vector: ML-DSA-44 cross-check' },
  { set: '65' as const, signer: ml_dsa65, message: 'circl interop vector: ML-DSA-65 cross-check' },
  { set: '87' as const, signer: ml_dsa87, message: 'circl interop vector: ML-DSA-87 cross-check' },
];

const mldsaSeeds = MLDSA_SETS.map(() => randomBytes(32));
const mldsaKeys = MLDSA_SETS.map(({ signer }, i) => signer.keygen(mldsaSeeds[i]));

const mldsaCirclRequests: CirclMldsaRequest[] = [];
for (let i = 0; i < MLDSA_SETS.length; i++) {
  const { signer, message } = MLDSA_SETS[i];
  const { publicKey, secretKey } = mldsaKeys[i];
  const msgBytes = new TextEncoder().encode(message);
  const sdkSig = signer.sign(msgBytes, secretKey);
  mldsaCirclRequests.push({
    set: MLDSA_SETS[i].set,
    pkHex: toHex(publicKey),
    skHex: toHex(secretKey),
    msgHex: toHex(msgBytes),
    sdkSigHex: toHex(sdkSig),
  });
}

const circlResp1 = callCircl({ mldsa: mldsaCirclRequests });

const mldsaResults: Array<{
  set: string;
  seedHex: string;
  publicKeyToken: string;
  message: string;
  sdkSignatureHex: string;
  circlSignatureHex: string;
}> = [];

for (let i = 0; i < MLDSA_SETS.length; i++) {
  const { set, message } = MLDSA_SETS[i];
  const { publicKey, secretKey } = mldsaKeys[i];
  const circlSet = circlResp1.mldsa.find((r) => r.set === set);
  if (!circlSet) fail(`ML-DSA-${set}: no CIRCL response`, {});

  const sdkSigHex = mldsaCirclRequests[i].sdkSigHex;

  // Direction A: SDK signs, CIRCL verifies the raw bytes.
  if (!circlSet.circlVerifiesSdkSig) {
    fail(`ML-DSA-${set}: CIRCL rejected the SDK's own signature`, {
      set,
      publicKeyHex: toHex(publicKey),
      messageHex: toHex(new TextEncoder().encode(message)),
      sdkSignatureHex: sdkSigHex,
    });
  }

  // Direction B: CIRCL signs, SDK verifies the raw bytes — via the actual
  // public pqc.verify entry point, not an internal bypass.
  const algorithm = `ml-dsa-${set === '44' ? '44' : set === '65' ? '65' : '87'}` as
    'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
  const pkKey = { algorithm, use: 'public' as const, bytes: publicKey };
  const circlSig = fromHex(circlSet.circlSigHex);
  const sdkAcceptsCirclSig = await pqc.verify(message, circlSig, pkKey);
  if (!sdkAcceptsCirclSig) {
    fail(`ML-DSA-${set}: the SDK's pqc.verify rejected CIRCL's own signature`, {
      set,
      publicKeyHex: toHex(publicKey),
      messageHex: toHex(new TextEncoder().encode(message)),
      circlSignatureHex: circlSet.circlSigHex,
    });
  }
  if (!circlSet.circlVerifiesOwnSig) {
    // Sanity check on CIRCL itself, not this SDK — if this ever fires, the
    // helper program has a bug, not the SDK.
    fail(`ML-DSA-${set}: CIRCL did not verify its own signature (helper bug, not an SDK finding)`, {
      set,
    });
  }

  mldsaResults.push({
    set,
    seedHex: toHex(mldsaSeeds[i]),
    publicKeyToken: pqc.keys.serialize({ algorithm, use: 'public', bytes: publicKey }),
    message,
    sdkSignatureHex: sdkSigHex,
    circlSignatureHex: circlSet.circlSigHex,
  });
  console.log(`ML-DSA-${set}: both directions cross-checked OK.`);
  void secretKey; // kept only long enough to sign above; never written to the fixture.
}

// ---------------------------------------------------------------------------
// Priority 2: X-Wing bidirectional shared-secret cross-check.
// ---------------------------------------------------------------------------

function runKemCrossCheck(
  label: string,
  kem: {
    keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
    encapsulate: (publicKey: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
    decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  },
  seed: Uint8Array,
): {
  seedHex: string;
  publicKeyHex: string;
  secretKeyHex: string;
  sdkCiphertextHex: string;
  sdkSharedSecretHex: string;
  circlCiphertextHex: string;
  circlSharedSecretHex: string;
} {
  const { publicKey, secretKey } = kem.keygen(seed);

  // Direction 1: SDK encapsulates, CIRCL decapsulates with the same secret key.
  const { cipherText: sdkCt, sharedSecret: sdkSs } = kem.encapsulate(publicKey);
  const resp = callCircl({
    [label]: { pkHex: toHex(publicKey), skHex: toHex(secretKey), sdkCtHex: toHex(sdkCt) },
  } as { mlkem?: CirclKemRequest; xwing?: CirclKemRequest });
  const kemResp = label === 'mlkem' ? resp.mlkem : resp.xwing;
  if (!kemResp) fail(`${label}: no CIRCL response`, {});

  if (!hexEqual(kemResp.circlDecapsOfSdkCtSsHex, toHex(sdkSs))) {
    fail(`${label}: CIRCL's decapsulation of the SDK's ciphertext disagrees on the shared secret`, {
      label,
      publicKeyHex: toHex(publicKey),
      sdkCiphertextHex: toHex(sdkCt),
      sdkSharedSecretHex: toHex(sdkSs),
      circlSharedSecretHex: kemResp.circlDecapsOfSdkCtSsHex,
    });
  }

  // Direction 2: CIRCL encapsulates fresh, SDK decapsulates with the same secret key.
  const circlCt = fromHex(kemResp.circlCtHex);
  const sdkSsOfCirclCt = kem.decapsulate(circlCt, secretKey);
  if (!hexEqual(toHex(sdkSsOfCirclCt), kemResp.circlSsHex)) {
    fail(`${label}: the SDK's decapsulation of CIRCL's ciphertext disagrees on the shared secret`, {
      label,
      publicKeyHex: toHex(publicKey),
      circlCiphertextHex: kemResp.circlCtHex,
      circlSharedSecretHex: kemResp.circlSsHex,
      sdkSharedSecretHex: toHex(sdkSsOfCirclCt),
    });
  }

  console.log(`${label}: both directions cross-checked OK.`);
  return {
    seedHex: toHex(seed),
    publicKeyHex: toHex(publicKey),
    secretKeyHex: toHex(secretKey),
    sdkCiphertextHex: toHex(sdkCt),
    sdkSharedSecretHex: toHex(sdkSs),
    circlCiphertextHex: kemResp.circlCtHex,
    circlSharedSecretHex: kemResp.circlSsHex,
  };
}

const xwingSeed = randomBytes(32); // x-wing keygen seed length (see docs/serialization-format.md §1)
const xwingResult = runKemCrossCheck('xwing', ml_kem768_x25519, xwingSeed);

// ---------------------------------------------------------------------------
// Priority 3: ML-KEM-768 bidirectional shared-secret cross-check.
// ---------------------------------------------------------------------------

const mlkemSeed = randomBytes(64); // ml-kem-768 keygen seed length (d || z, 32 + 32)
const mlkemResult = runKemCrossCheck('mlkem', ml_kem768, mlkemSeed);

// ---------------------------------------------------------------------------
// Write the three vector files.
// ---------------------------------------------------------------------------

mkdirSync(VECTORS_DIR, { recursive: true });

const generatedAt = new Date().toISOString();
const circlVersion = circlResp1.circlVersion;

function writeVectorFile(name: string, payload: Record<string, unknown>): void {
  const path = join(VECTORS_DIR, name);
  const doc = {
    meta: {
      generatedWith: `@pqc-sdk/core@${version}`,
      counterpart: 'github.com/cloudflare/circl',
      counterpartVersion: circlVersion,
      generatedAt,
      regenerateCommand: REGENERATE_COMMAND,
      note:
        'Cross-implementation interop vector: this SDK vs. Cloudflare CIRCL (Go), an ' +
        'independent codebase from @noble/post-quantum. Not an ACVP vector — see ' +
        'src/nist-vectors.test.ts and docs/compliance/ for those. The cross-check that ' +
        'matters (does CIRCL accept/produce byte-compatible material) was performed once, ' +
        "here, at generation time; CI re-checks only this SDK's own behaviour against the " +
        'committed bytes (a regression guard), since Go/CIRCL never runs in CI.',
    },
    ...payload,
  };
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`generate-circl-vectors: wrote ${path}`);
}

writeVectorFile('circl-mldsa.json', { cases: mldsaResults });
writeVectorFile('circl-xwing.json', { case: xwingResult });
writeVectorFile('circl-mlkem768.json', { case: mlkemResult });

console.log('generate-circl-vectors: all cross-checks passed.');
