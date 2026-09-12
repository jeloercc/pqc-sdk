#!/usr/bin/env -S pnpm exec tsx
/**
 * Generates the BouncyCastle interop cross-check vectors under
 * src/vectors/interop/{bc-mldsa,bc-mlkem768}.json.
 *
 * A second, independent counterpart alongside CIRCL (Go) —
 * generate-circl-vectors.mts. No X-Wing here: BouncyCastle does not
 * implement it. Otherwise this mirrors that script's design exactly; see its
 * header for the full rationale (why this isn't an ACVP vector, why Java
 * stays out of CI, why a mismatch is a finding to report rather than patch
 * around). The short version, restated because it matters every time this
 * runs: this script performs the actual cross-implementation check ONCE,
 * locally, and commits the result; CI only re-checks the committed bytes
 * against this SDK's own code afterward.
 *
 * If ANY cross-check fails, this script exits non-zero and writes nothing.
 *
 * Deterministic, verified the same way as the CIRCL vectors: every keygen,
 * sign and encapsulate call (both SDK and BC sides) uses a fixed seed via
 * `fixedSeed()` / `{ extraEntropy: false }` on the SDK side, and BC's
 * MLDSASigner initialized with no SecureRandom (leaves FIPS 204's `rnd`
 * zeroed — confirmed by reading MLDSASigner.java before writing this) /
 * MLKEMGenerator.internalGenerateEncapsulated's explicit randBytes parameter
 * on the BC side. Running this script twice produces byte-identical output
 * except `meta.generatedAt` — verified by diffing two consecutive runs
 * before this was committed.
 *
 * Prerequisites:
 *   - `pnpm --filter @pqc-sdk/core build` (public pqc.sign/pqc.verify calls,
 *     same as generate-circl-vectors.mts)
 *   - A JDK on PATH, and the helper fetched/compiled once:
 *     `cd scripts/interop/bc-helper && ./fetch-bcprov.sh && javac -cp bcprov-jdk18on-1.86.jar BCHelper.java`
 *   - Runs under `tsx`, not plain `node` — same reason as
 *     generate-circl-vectors.mts (this repo's `.js`-for-sibling-`.ts` import
 *     convention).
 *
 * Usage (from packages/core): pnpm exec tsx scripts/interop/generate-bc-vectors.mts
 */

import { execFileSync } from 'node:child_process';
import console from 'node:console';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { pqc, version } from '@pqc-sdk/core';

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../../src/vendor/ml-dsa/ml-dsa.ts';
import { ml_kem768 } from '../../src/vendor/ml-kem/ml-kem.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const BC_DIR = join(HERE, 'bc-helper');
const BC_JAR = join(BC_DIR, 'bcprov-jdk18on-1.86.jar');
const BC_CLASS = join(BC_DIR, 'BCHelper.class');
const VECTORS_DIR = join(HERE, '../../src/vectors/interop');

const REGENERATE_COMMAND =
  'cd packages/core && pnpm build && ' +
  '(cd scripts/interop/bc-helper && ./fetch-bcprov.sh && javac -cp bcprov-jdk18on-1.86.jar BCHelper.java) && ' +
  'pnpm exec tsx scripts/interop/generate-bc-vectors.mts';

/**
 * Fixed, obviously synthetic byte sequence (test fixtures only — never a real
 * key or secret). `marker` offsets the pattern so nothing here can be
 * mistaken for accidental key/seed reuse. Distinct marker range from
 * generate-circl-vectors.mts's (0x10-0x52) so the two scripts' fixtures never
 * coincidentally share a seed even though they cover overlapping algorithms.
 */
function fixedSeed(length: number, marker: number): Uint8Array {
  return new Uint8Array(length).map((_, i) => (i + marker) & 0xff);
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}
function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
function hexEqual(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

if (!existsSync(BC_JAR) || !existsSync(BC_CLASS)) {
  console.error(
    `generate-bc-vectors: ${BC_JAR} and/or ${BC_CLASS} not found. Set up first:\n` +
      '  cd scripts/interop/bc-helper && ./fetch-bcprov.sh && ' +
      'javac -cp bcprov-jdk18on-1.86.jar BCHelper.java',
  );
  process.exit(1);
}

function fail(label: string, detail: Record<string, unknown>): never {
  console.error(`generate-bc-vectors: CROSS-CHECK FAILED — ${label}`);
  console.error(JSON.stringify(detail, null, 2));
  console.error(
    'This is a finding, not a test bug. Nothing was written. Do not adjust this ' +
      'script to make the mismatch disappear — report it.',
  );
  process.exit(1);
}

function callBC(...args: string[]): string {
  return execFileSync('java', ['-cp', `${BC_JAR}:${BC_DIR}`, 'BCHelper', ...args], {
    encoding: 'utf8',
  }).trim();
}

const bcVersion = callBC('version');

// ---------------------------------------------------------------------------
// ML-DSA-44/65/87 signature generation, both directions.
// ---------------------------------------------------------------------------

const MLDSA_SETS = [
  {
    set: '44' as const,
    signer: ml_dsa44,
    message: 'bc interop vector: ML-DSA-44 cross-check',
    seedMarker: 0x60,
  },
  {
    set: '65' as const,
    signer: ml_dsa65,
    message: 'bc interop vector: ML-DSA-65 cross-check',
    seedMarker: 0x70,
  },
  {
    set: '87' as const,
    signer: ml_dsa87,
    message: 'bc interop vector: ML-DSA-87 cross-check',
    seedMarker: 0x80,
  },
];

const mldsaResults: Array<{
  set: string;
  seedHex: string;
  publicKeyToken: string;
  message: string;
  sdkSignatureHex: string;
  bcSignatureHex: string;
}> = [];

for (const { set, signer, message, seedMarker } of MLDSA_SETS) {
  const seed = fixedSeed(32, seedMarker);
  const { publicKey, secretKey } = signer.keygen(seed);
  const msgBytes = new TextEncoder().encode(message);

  // extraEntropy: false selects FIPS 204's deterministic variant (rnd = 0^32) —
  // used ONLY here, for a reproducible fixture. See generate-circl-vectors.mts
  // for why this is never the SDK's production signing path.
  const sdkSig = signer.sign(msgBytes, secretKey, { extraEntropy: false });

  // Direction A: SDK signs, BC verifies the raw bytes.
  const bcVerifiesSdkSig = callBC(
    'mldsa-verify',
    set,
    toHex(publicKey),
    toHex(msgBytes),
    toHex(sdkSig),
  );
  if (bcVerifiesSdkSig !== 'true') {
    fail(`ML-DSA-${set}: BC rejected the SDK's own signature`, {
      set,
      publicKeyHex: toHex(publicKey),
      messageHex: toHex(msgBytes),
      sdkSignatureHex: toHex(sdkSig),
    });
  }

  // BC signs deterministically (no SecureRandom passed — see BCHelper.mldsaSign).
  const bcSigHex = callBC('mldsa-sign', set, toHex(secretKey), toHex(msgBytes));
  const bcSig = fromHex(bcSigHex);

  // Direction B: BC signs, SDK verifies the raw bytes — via the actual public
  // pqc.verify entry point, not an internal bypass.
  const algorithm = `ml-dsa-${set}` as 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
  const pkKey = { algorithm, use: 'public' as const, bytes: publicKey };
  const sdkAcceptsBcSig = await pqc.verify(message, bcSig, pkKey);
  if (!sdkAcceptsBcSig) {
    fail(`ML-DSA-${set}: the SDK's pqc.verify rejected BC's own signature`, {
      set,
      publicKeyHex: toHex(publicKey),
      messageHex: toHex(msgBytes),
      bcSignatureHex: bcSigHex,
    });
  }

  // Sanity check on BC itself, not this SDK — if this ever fires, the helper
  // program has a bug, not the SDK.
  const bcVerifiesOwnSig = callBC('mldsa-verify', set, toHex(publicKey), toHex(msgBytes), bcSigHex);
  if (bcVerifiesOwnSig !== 'true') {
    fail(`ML-DSA-${set}: BC did not verify its own signature (helper bug, not an SDK finding)`, {
      set,
    });
  }

  mldsaResults.push({
    set,
    seedHex: toHex(seed),
    publicKeyToken: pqc.keys.serialize({ algorithm, use: 'public', bytes: publicKey }),
    message,
    sdkSignatureHex: toHex(sdkSig),
    bcSignatureHex: bcSigHex,
  });
  console.log(`ML-DSA-${set}: both directions cross-checked OK against BouncyCastle.`);
}

// ---------------------------------------------------------------------------
// ML-KEM-768 bidirectional shared-secret cross-check.
// ---------------------------------------------------------------------------

// ml-kem-768 keygen seed is 64 bytes (d || z, 32 + 32); its encapsulate()
// takes a 32-byte seed (ml_kem768.lengths.msgRand — see
// generate-circl-vectors.mts, already confirmed there).
const mlkemKeygenSeed = fixedSeed(64, 0x90);
const mlkemSdkEncapsSeed = fixedSeed(32, 0x91);
const mlkemBcEncapsSeed = fixedSeed(32, 0x92);

const { publicKey: mlkemPk, secretKey: mlkemSk } = ml_kem768.keygen(mlkemKeygenSeed);

// Direction 1: SDK encapsulates, BC decapsulates with the same secret key.
const { cipherText: sdkCt, sharedSecret: sdkSs } = ml_kem768.encapsulate(
  mlkemPk,
  mlkemSdkEncapsSeed,
);
const bcDecapsOfSdkCtHex = callBC('mlkem-decapsulate', toHex(mlkemSk), toHex(sdkCt));
if (!hexEqual(bcDecapsOfSdkCtHex, toHex(sdkSs))) {
  fail("ML-KEM-768: BC's decapsulation of the SDK's ciphertext disagrees on the shared secret", {
    publicKeyHex: toHex(mlkemPk),
    sdkCiphertextHex: toHex(sdkCt),
    sdkSharedSecretHex: toHex(sdkSs),
    bcSharedSecretHex: bcDecapsOfSdkCtHex,
  });
}

// Direction 2: BC encapsulates (fixed seed), SDK decapsulates with the same secret key.
const bcEncapsOut = callBC('mlkem-encapsulate', toHex(mlkemPk), toHex(mlkemBcEncapsSeed));
const [bcCtHex, bcSsHex] = bcEncapsOut.split(' ');
if (!bcCtHex || !bcSsHex) {
  fail('ML-KEM-768: unexpected BCHelper mlkem-encapsulate output', { bcEncapsOut });
}
const sdkSsOfBcCt = ml_kem768.decapsulate(fromHex(bcCtHex), mlkemSk);
if (!hexEqual(toHex(sdkSsOfBcCt), bcSsHex)) {
  fail("ML-KEM-768: the SDK's decapsulation of BC's ciphertext disagrees on the shared secret", {
    publicKeyHex: toHex(mlkemPk),
    bcCiphertextHex: bcCtHex,
    bcSharedSecretHex: bcSsHex,
    sdkSharedSecretHex: toHex(sdkSsOfBcCt),
  });
}

console.log('ML-KEM-768: both directions cross-checked OK against BouncyCastle.');

const mlkemResult = {
  seedHex: toHex(mlkemKeygenSeed),
  publicKeyHex: toHex(mlkemPk),
  secretKeyHex: toHex(mlkemSk),
  sdkCiphertextHex: toHex(sdkCt),
  sdkSharedSecretHex: toHex(sdkSs),
  bcCiphertextHex: bcCtHex,
  bcSharedSecretHex: bcSsHex,
};

// ---------------------------------------------------------------------------
// Write the two vector files.
// ---------------------------------------------------------------------------

mkdirSync(VECTORS_DIR, { recursive: true });

const generatedAt = new Date().toISOString();

function writeVectorFile(name: string, payload: Record<string, unknown>): void {
  const path = join(VECTORS_DIR, name);
  const doc = {
    meta: {
      generatedWith: `@pqc-sdk/core@${version}`,
      counterpart: 'org.bouncycastle:bcprov-jdk18on',
      counterpartVersion: bcVersion,
      generatedAt,
      regenerateCommand: REGENERATE_COMMAND,
      note:
        'Cross-implementation interop vector: this SDK vs. BouncyCastle (Java), a second ' +
        'independent codebase alongside CIRCL (Go) — see circl-*.json in this directory. ' +
        'Not an ACVP vector — see src/nist-vectors.test.ts and docs/compliance/ for those. ' +
        'Uses the non-deprecated org.bouncycastle.crypto.{signers,kems}/params API (FIPS ' +
        '203/204 final names), not the older org.bouncycastle.pqc.crypto.{mlkem,mldsa} ' +
        'classes of the same name (deprecated in favor of these) and never the legacy ' +
        'round-3 "Dilithium"/"Kyber" classes, which are a different algorithm. The ' +
        'cross-check that matters (does BC accept/produce byte-compatible material) was ' +
        "performed once, here, at generation time; CI re-checks only this SDK's own " +
        'behaviour against the committed bytes (a regression guard), since Java/BC never ' +
        'runs in CI.',
    },
    ...payload,
  };
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`generate-bc-vectors: wrote ${path}`);
}

writeVectorFile('bc-mldsa.json', { cases: mldsaResults });
writeVectorFile('bc-mlkem768.json', { case: mlkemResult });

console.log('generate-bc-vectors: all cross-checks passed.');
