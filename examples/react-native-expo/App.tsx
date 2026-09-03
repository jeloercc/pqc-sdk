// Import order matters, twice over:
//
// 1. The entropy polyfill must patch `crypto.getRandomValues` with native OS
//    randomness (SecRandomCopyBytes / SecureRandom) before the SDK runs any
//    key generation. Hermes does not ship `crypto.getRandomValues` at all.
// 2. The async-iterator alias must be installed before `@pqc-sdk/core` is
//    evaluated, or the streaming API's explicit `Symbol.asyncIterator`
//    lookups resolve to `undefined` on Hermes. See asyncIteratorPolyfill.ts.
import 'react-native-get-random-values';
import { ASYNC_ITERATOR_IS_POLYFILLED } from './asyncIteratorPolyfill';

import { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';

import { pqc, PqcError, type KemAlgorithm, type KeyPair } from '@pqc-sdk/core';

type StepStatus = 'pending' | 'running' | 'pass' | 'fail';

interface Step {
  name: string;
  status: StepStatus;
  ms?: number;
  detail?: string;
}

/**
 * Every ⏳ row issue #45 tracks, in one run: both KEMs one-shot, both KEMs
 * streamed, and the fail-closed behaviour that makes the streaming envelope
 * worth anything. Signatures stay in because this screen is also the general
 * RN validation for the SDK, not only the streaming one.
 */
const STEP_NAMES = [
  'ML-KEM-768: generate',
  'ML-KEM-768: encrypt + decrypt',
  'X-Wing: generate',
  'X-Wing: encrypt + decrypt',
  'ML-DSA-65: generate + sign',
  'ML-DSA-65: verify',
  'Streaming (ML-KEM-768): roundtrip',
  'Streaming (X-Wing): roundtrip',
  'Streaming: tampered chunk fails closed',
] as const;

const INITIAL_STEPS: Step[] = STEP_NAMES.map((name) => ({ name, status: 'pending' }));

// 4 KiB in 1 KiB chunks: four chunks, so the chunk counter, the final-chunk
// flag and the chunk-to-chunk chaining all actually get exercised. Small on
// purpose — this proves chunking works on Hermes, it is not a throughput test.
const STREAM_PAYLOAD_BYTES = 4096;
const STREAM_CHUNK_SIZE = 1024;

function assertBytesEqual(a: Uint8Array, b: Uint8Array): void {
  if (a.length !== b.length) throw new Error(`length mismatch: ${a.length} vs ${b.length}`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`byte mismatch at index ${i}`);
  }
}

function syntheticPayload(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  // A varying pattern rather than a constant fill, so a chunk silently
  // dropped or reordered would change the bytes rather than compare equal.
  for (let i = 0; i < length; i++) bytes[i] = (i * 31 + 7) % 256;
  return bytes;
}

// eslint-disable-next-line @typescript-eslint/require-await
async function* single(data: Uint8Array): AsyncGenerator<Uint8Array> {
  yield data;
}

async function collect(chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
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

export default function App() {
  const [steps, setSteps] = useState<Step[]>(INITIAL_STEPS);
  const [running, setRunning] = useState(false);
  const [environment, setEnvironment] = useState<string[]>([]);

  const updateStep = useCallback((index: number, patch: Partial<Step>) => {
    setSteps((prev) => prev.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  }, []);

  /**
   * Runs one step, recording its duration and marking it failed with the
   * error text rather than letting a throw escape — a step failing should
   * show up as a red row on the screen, which is the whole point of running
   * this on a device, instead of an unhandled rejection with no UI.
   */
  const step = useCallback(
    async (index: number, run: () => Promise<string | undefined>): Promise<boolean> => {
      updateStep(index, { status: 'running' });
      const started = Date.now();
      try {
        const detail = await run();
        updateStep(index, { status: 'pass', ms: Date.now() - started, detail });
        return true;
      } catch (error) {
        updateStep(index, {
          status: 'fail',
          ms: Date.now() - started,
          detail: String(error),
        });
        return false;
      }
    },
    [updateStep],
  );

  const runAll = useCallback(async () => {
    setRunning(true);
    setSteps(INITIAL_STEPS);

    setEnvironment([
      `Symbol.asyncIterator: ${
        ASYNC_ITERATOR_IS_POLYFILLED
          ? 'absent natively, aliased to "@@asyncIterator" (expected on Hermes)'
          : 'provided natively by this engine'
      }`,
      `TextDecoder: ${typeof TextDecoder === 'undefined' ? 'absent (byte comparison used instead)' : 'available'}`,
      `TransformStream: ${
        typeof TransformStream === 'undefined'
          ? 'absent — the Web Streams adapters cannot run here; the async-iterable core is used directly'
          : 'available'
      }`,
    ]);

    const message = 'roundtrip on a real React Native app (Expo + Hermes)';
    const utf8 = new TextEncoder().encode(message);

    // --- ML-KEM-768 and X-Wing, one-shot -----------------------------------
    const pairs: Partial<Record<KemAlgorithm, KeyPair<KemAlgorithm>>> = {};

    const kems: Array<{ algorithm: KemAlgorithm; generateAt: number; roundtripAt: number }> = [
      { algorithm: 'ml-kem-768', generateAt: 0, roundtripAt: 1 },
      { algorithm: 'x-wing', generateAt: 2, roundtripAt: 3 },
    ];

    for (const { algorithm, generateAt, roundtripAt } of kems) {
      const generated = await step(generateAt, async () => {
        const pair = await pqc.keys.generate({ algorithm });
        pairs[algorithm] = pair;
        return `${algorithm}, public ${pair.publicKey.bytes.length} B, secret ${pair.secretKey.bytes.length} B`;
      });
      if (!generated) continue;

      await step(roundtripAt, async () => {
        const pair = pairs[algorithm]!;
        const ciphertext = await pqc.encrypt(message, pair.publicKey);
        const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
        assertBytesEqual(plaintext, utf8);
        return `envelope ${ciphertext.length} B, plaintext matches`;
      });
    }

    // --- ML-DSA-65 ---------------------------------------------------------
    let signer: KeyPair<'ml-dsa-65'> | undefined;
    let signature: Awaited<ReturnType<typeof pqc.sign>> | undefined;

    await step(4, async () => {
      signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
      signature = await pqc.sign(message, signer.secretKey);
      return `signature ${signature.length} B`;
    });

    await step(5, async () => {
      if (!signer || !signature) throw new Error('signing step did not complete');
      const valid = await pqc.verify(message, signature, signer.publicKey);
      if (!valid) throw new Error('signature did not verify');
      return 'signature verified';
    });

    // --- Streaming, both KEMs ----------------------------------------------
    const payload = syntheticPayload(STREAM_PAYLOAD_BYTES);
    const streaming: Array<{ algorithm: KemAlgorithm; at: number }> = [
      { algorithm: 'ml-kem-768', at: 6 },
      { algorithm: 'x-wing', at: 7 },
    ];

    for (const { algorithm, at } of streaming) {
      await step(at, async () => {
        const pair = pairs[algorithm];
        if (!pair) throw new Error(`no ${algorithm} key pair: its generate step failed`);
        const ciphertext = await collect(
          pqc.encryptStream(pair.publicKey, single(payload), { chunkSize: STREAM_CHUNK_SIZE }),
        );
        const decrypted = await collect(pqc.decryptStream(pair.secretKey, single(ciphertext)));
        assertBytesEqual(decrypted, payload);
        const chunks = Math.ceil(STREAM_PAYLOAD_BYTES / STREAM_CHUNK_SIZE);
        return `${STREAM_PAYLOAD_BYTES} B in ${chunks} chunks → ${ciphertext.length} B, plaintext matches`;
      });
    }

    // --- Fail-closed -------------------------------------------------------
    await step(8, async () => {
      const pair = pairs['ml-kem-768'];
      if (!pair) throw new Error('no ml-kem-768 key pair: its generate step failed');
      const ciphertext = await collect(
        pqc.encryptStream(pair.publicKey, single(payload), { chunkSize: STREAM_CHUNK_SIZE }),
      );
      // Flip a bit in the final chunk's authentication tag.
      ciphertext[ciphertext.length - 1] ^= 0x01;
      try {
        await collect(pqc.decryptStream(pair.secretKey, single(ciphertext)));
      } catch (error) {
        if (error instanceof PqcError && error.code === 'DECRYPTION_FAILED') {
          return 'rejected with PqcError DECRYPTION_FAILED, as it must';
        }
        throw new Error(`threw, but not a PqcError DECRYPTION_FAILED: ${String(error)}`);
      }
      throw new Error('tampered stream decrypted without error — the envelope is not fail-closed');
    });

    setRunning(false);
  }, [step]);

  useEffect(() => {
    runAll();
  }, [runAll]);

  const allDone = !running && steps.every((s) => s.status === 'pass' || s.status === 'fail');
  const allPass = allDone && steps.every((s) => s.status === 'pass');
  const failures = steps.filter((s) => s.status === 'fail').length;

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <StatusBar style="auto" />
      <Text style={styles.title}>@pqc-sdk/core — React Native validation</Text>
      <Text style={styles.subtitle}>
        ML-KEM-768, X-Wing, ML-DSA-65 and the streaming envelope. Entropy:
        react-native-get-random-values (native OS randomness, not Math.random).
      </Text>

      {allDone && (
        <View style={[styles.banner, allPass ? styles.bannerPass : styles.bannerFail]}>
          <Text style={styles.bannerText}>
            {allPass ? '✅ PASS' : `❌ FAIL (${failures}/${steps.length})`}
          </Text>
        </View>
      )}

      {steps.map((s, i) => (
        <View key={i} style={styles.row}>
          <Text style={styles.stepName}>{s.name}</Text>
          <View style={styles.stepRight}>
            {s.status === 'running' && <ActivityIndicator size="small" />}
            {s.status === 'pass' && (
              <Text style={styles.pass}>PASS{s.ms !== undefined ? ` (${s.ms} ms)` : ''}</Text>
            )}
            {s.status === 'fail' && (
              <Text style={styles.fail}>FAIL{s.ms !== undefined ? ` (${s.ms} ms)` : ''}</Text>
            )}
            {s.status === 'pending' && <Text style={styles.pending}>—</Text>}
          </View>
          {s.detail && (
            <Text style={s.status === 'fail' ? styles.failDetail : styles.detail}>{s.detail}</Text>
          )}
        </View>
      ))}

      {running && <Text style={styles.note}>Running…</Text>}

      {environment.length > 0 && (
        <View style={styles.environment}>
          <Text style={styles.environmentTitle}>Runtime</Text>
          {environment.map((line, i) => (
            <Text key={i} style={styles.note}>
              {line}
            </Text>
          ))}
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    paddingTop: 64,
    paddingHorizontal: 20,
    paddingBottom: 40,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 12,
    color: '#666',
    marginBottom: 20,
  },
  banner: {
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 20,
  },
  bannerPass: { backgroundColor: '#d1f7d6' },
  bannerFail: { backgroundColor: '#f7d1d1' },
  bannerText: { fontSize: 20, fontWeight: '800' },
  row: {
    paddingVertical: 10,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#ddd',
  },
  stepRight: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 4,
  },
  stepName: { fontSize: 14, fontWeight: '600' },
  pass: { color: '#1a7f37', fontWeight: '700' },
  fail: { color: '#c0392b', fontWeight: '700' },
  pending: { color: '#999' },
  detail: { fontSize: 12, color: '#666', marginTop: 2 },
  failDetail: { fontSize: 12, color: '#c0392b', marginTop: 2 },
  note: { fontSize: 12, color: '#666', marginTop: 6, fontStyle: 'italic' },
  environment: {
    marginTop: 24,
    paddingTop: 12,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#ddd',
  },
  environmentTitle: { fontSize: 13, fontWeight: '700', color: '#444' },
});
