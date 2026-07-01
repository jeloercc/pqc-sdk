// Import order matters: the entropy polyfill must patch `crypto.getRandomValues`
// with native OS randomness (SecRandomCopyBytes / SecureRandom) before the SDK
// runs any key generation. Hermes does not ship `crypto.getRandomValues` at all.
import 'react-native-get-random-values';

import { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, ScrollView, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';

import { pqc, type KeyPair } from '@pqc-sdk/core';

type StepStatus = 'pending' | 'running' | 'pass' | 'fail';

interface Step {
  name: string;
  status: StepStatus;
  ms?: number;
  detail?: string;
}

const INITIAL_STEPS: Step[] = [
  { name: 'ML-KEM-768: generate', status: 'pending' },
  { name: 'ML-KEM-768: encrypt', status: 'pending' },
  { name: 'ML-KEM-768: decrypt', status: 'pending' },
  { name: 'ML-KEM-768: plaintext matches', status: 'pending' },
  { name: 'ML-DSA-65: generate + sign', status: 'pending' },
  { name: 'ML-DSA-65: verify', status: 'pending' },
];

function assertBytesEqual(a: Uint8Array, b: Uint8Array): void {
  if (a.length !== b.length) throw new Error(`length mismatch: ${a.length} vs ${b.length}`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`byte mismatch at index ${i}`);
  }
}

export default function App() {
  const [steps, setSteps] = useState<Step[]>(INITIAL_STEPS);
  const [running, setRunning] = useState(false);
  const [textDecoderNote, setTextDecoderNote] = useState<string>('');

  const updateStep = useCallback((index: number, patch: Partial<Step>) => {
    setSteps((prev) => prev.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  }, []);

  const runAll = useCallback(async () => {
    setRunning(true);
    setSteps(INITIAL_STEPS);

    const message = 'roundtrip on a real React Native app (Expo + Hermes)';
    const utf8 = new TextEncoder().encode(message);

    setTextDecoderNote(
      typeof TextDecoder === 'undefined'
        ? 'TextDecoder is not defined in this runtime (expected on Hermes without a polyfill); using byte comparison instead.'
        : 'TextDecoder is available in this runtime.',
    );

    let pair: KeyPair<'ml-kem-768'> | undefined;
    let ciphertext: Awaited<ReturnType<typeof pqc.encrypt>> | undefined;
    let plaintext: Awaited<ReturnType<typeof pqc.decrypt>> | undefined;

    try {
      updateStep(0, { status: 'running' });
      let t = Date.now();
      pair = await pqc.keys.generate();
      updateStep(0, { status: 'pass', ms: Date.now() - t, detail: pair.algorithm });
    } catch (error) {
      updateStep(0, { status: 'fail', detail: String(error) });
      setRunning(false);
      return;
    }

    try {
      updateStep(1, { status: 'running' });
      const t = Date.now();
      ciphertext = await pqc.encrypt(message, pair.publicKey);
      updateStep(1, { status: 'pass', ms: Date.now() - t, detail: `${ciphertext.length} bytes` });
    } catch (error) {
      updateStep(1, { status: 'fail', detail: String(error) });
      setRunning(false);
      return;
    }

    try {
      updateStep(2, { status: 'running' });
      const t = Date.now();
      plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
      updateStep(2, { status: 'pass', ms: Date.now() - t });
    } catch (error) {
      updateStep(2, { status: 'fail', detail: String(error) });
      setRunning(false);
      return;
    }

    try {
      assertBytesEqual(plaintext, utf8);
      updateStep(3, { status: 'pass' });
    } catch (error) {
      updateStep(3, { status: 'fail', detail: String(error) });
      setRunning(false);
      return;
    }

    let signer: KeyPair<'ml-dsa-65'> | undefined;
    let signature: Awaited<ReturnType<typeof pqc.sign>> | undefined;

    try {
      updateStep(4, { status: 'running' });
      const t = Date.now();
      signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
      signature = await pqc.sign(message, signer.secretKey);
      updateStep(4, { status: 'pass', ms: Date.now() - t, detail: `${signature.length} bytes` });
    } catch (error) {
      updateStep(4, { status: 'fail', detail: String(error) });
      setRunning(false);
      return;
    }

    try {
      updateStep(5, { status: 'running' });
      const t = Date.now();
      const valid = await pqc.verify(message, signature, signer.publicKey);
      if (!valid) throw new Error('signature did not verify');
      updateStep(5, { status: 'pass', ms: Date.now() - t });
    } catch (error) {
      updateStep(5, { status: 'fail', detail: String(error) });
    }

    setRunning(false);
  }, [updateStep]);

  useEffect(() => {
    runAll();
  }, [runAll]);

  const allDone = steps.every((s) => s.status === 'pass' || s.status === 'fail');
  const allPass = allDone && steps.every((s) => s.status === 'pass');
  const anyFail = steps.some((s) => s.status === 'fail');

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <StatusBar style="auto" />
      <Text style={styles.title}>@pqc-sdk/core — React Native validation</Text>
      <Text style={styles.subtitle}>
        Entropy source: react-native-get-random-values (native OS randomness, not Math.random)
      </Text>

      {allDone && (
        <View style={[styles.banner, allPass ? styles.bannerPass : styles.bannerFail]}>
          <Text style={styles.bannerText}>{allPass ? '✅ PASS' : '❌ FAIL'}</Text>
        </View>
      )}

      {steps.map((step, i) => (
        <View key={i} style={styles.row}>
          <Text style={styles.stepName}>{step.name}</Text>
          <View style={styles.stepRight}>
            {step.status === 'running' && <ActivityIndicator size="small" />}
            {step.status === 'pass' && (
              <Text style={styles.pass}>PASS{step.ms !== undefined ? ` (${step.ms} ms)` : ''}</Text>
            )}
            {step.status === 'fail' && <Text style={styles.fail}>FAIL</Text>}
            {step.status === 'pending' && <Text style={styles.pending}>—</Text>}
          </View>
          {step.detail && (
            <Text style={step.status === 'fail' ? styles.failDetail : styles.detail}>
              {step.detail}
            </Text>
          )}
        </View>
      ))}

      {anyFail === false && allDone && <Text style={styles.note}>{textDecoderNote}</Text>}

      {running && <Text style={styles.note}>Running…</Text>}
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
  note: { fontSize: 12, color: '#666', marginTop: 16, fontStyle: 'italic' },
});
