/**
 * Smoke tests for @pqc-sdk/langchain tools.
 *
 * Each tool is invoked directly via tool.invoke() — no LLM or agent
 * runtime needed. This confirms:
 *   - correct output shape
 *   - round-trip keygen → encrypt → decrypt
 *   - round-trip keygen → sign → verify
 *   - tamper detection (decrypt + verify)
 *   - PqcError surfaces as a structured message
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { FIPS_ALGORITHMS, SUPPORTED_ALGORITHMS } from '@pqc-sdk/core';

import {
  pqcAlgorithmsTool,
  pqcDecryptTool,
  pqcEncryptTool,
  pqcKeygenTool,
  pqcSignTool,
  pqcTools,
  pqcVerifyTool,
} from './index.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

function parse<T>(json: unknown): T {
  if (typeof json !== 'string') throw new Error(`Expected string, got ${typeof json}`);
  return JSON.parse(json) as T;
}

// ─── pqcAlgorithmsTool ───────────────────────────────────────────────────────

describe('pqcAlgorithmsTool', () => {
  it('returns supported and fips arrays', async () => {
    const result = await pqcAlgorithmsTool.invoke({});
    const data = parse<{ supported: string[]; fips: string[] }>(result);
    expect(data.supported).toEqual([...SUPPORTED_ALGORITHMS]);
    expect(data.fips).toEqual([...FIPS_ALGORITHMS]);
    expect(data.fips).not.toContain('x-wing');
    expect(data.supported).toContain('x-wing');
  });
});

// ─── pqcKeygenTool ───────────────────────────────────────────────────────────

describe('pqcKeygenTool', () => {
  it('generates an x-wing pair by default', async () => {
    const result = await pqcKeygenTool.invoke({ algorithm: 'x-wing' });
    const data = parse<{ algorithm: string; publicToken: string; secretToken: string }>(result);
    expect(data.algorithm).toBe('x-wing');
    expect(data.publicToken).toMatch(/^pqcv1\.x-wing\.public\./);
    expect(data.secretToken).toMatch(/^pqcv1\.x-wing\.secret\./);
  });

  it('generates ml-kem-768', async () => {
    const result = await pqcKeygenTool.invoke({ algorithm: 'ml-kem-768' });
    const data = parse<{ publicToken: string }>(result);
    expect(data.publicToken).toMatch(/^pqcv1\.ml-kem-768\.public\./);
  });

  it('generates ml-dsa-65', async () => {
    const result = await pqcKeygenTool.invoke({ algorithm: 'ml-dsa-65' });
    const data = parse<{ publicToken: string }>(result);
    expect(data.publicToken).toMatch(/^pqcv1\.ml-dsa-65\.public\./);
  });

  it('throws a Zod schema error for unknown algorithm (caught before handler)', async () => {
    // LangChain validates the Zod schema before invoking the handler, so an
    // unknown algorithm string is rejected at the schema level — not as a
    // PqcError. This is correct: the enum acts as a first line of defense.
    await expect(
      pqcKeygenTool.invoke({ algorithm: 'ml-kem-9999' as 'ml-kem-768' }),
    ).rejects.toThrow(/schema|enum|invalid/i);
  });
});

// ─── pqcEncryptTool / pqcDecryptTool ─────────────────────────────────────────

describe('pqcEncryptTool / pqcDecryptTool', () => {
  it('round-trips a message with ml-kem-768', async () => {
    const keyResult = await pqcKeygenTool.invoke({ algorithm: 'ml-kem-768' });
    const { publicToken, secretToken } = parse<{
      publicToken: string;
      secretToken: string;
    }>(keyResult);

    const encResult = await pqcEncryptTool.invoke({
      plaintext: 'hello langchain agent',
      publicToken,
    });
    const { ciphertextHex } = parse<{ ciphertextHex: string }>(encResult);
    expect(ciphertextHex.length).toBeGreaterThan(0);

    const decResult = await pqcDecryptTool.invoke({ ciphertextHex, secretToken });
    const { plaintext } = parse<{ plaintext: string }>(decResult);
    expect(plaintext).toBe('hello langchain agent');
  });

  it('round-trips a message with x-wing', async () => {
    const keyResult = await pqcKeygenTool.invoke({ algorithm: 'x-wing' });
    const { publicToken, secretToken } = parse<{
      publicToken: string;
      secretToken: string;
    }>(keyResult);
    const encResult = await pqcEncryptTool.invoke({ plaintext: 'x-wing message', publicToken });
    const { ciphertextHex } = parse<{ ciphertextHex: string }>(encResult);
    const decResult = await pqcDecryptTool.invoke({ ciphertextHex, secretToken });
    const { plaintext } = parse<{ plaintext: string }>(decResult);
    expect(plaintext).toBe('x-wing message');
  });

  it('throws PqcError[DECRYPTION_FAILED] on tampered ciphertext', async () => {
    const keyResult = await pqcKeygenTool.invoke({ algorithm: 'ml-kem-768' });
    const { publicToken, secretToken } = parse<{
      publicToken: string;
      secretToken: string;
    }>(keyResult);
    const encResult = await pqcEncryptTool.invoke({ plaintext: 'secret', publicToken });
    const { ciphertextHex } = parse<{ ciphertextHex: string }>(encResult);

    const bytes = hexToBytes(ciphertextHex);
    bytes[bytes.length - 1]! ^= 0xff;
    const tampered = bytesToHex(bytes);

    await expect(pqcDecryptTool.invoke({ ciphertextHex: tampered, secretToken })).rejects.toThrow(
      'PqcError[DECRYPTION_FAILED]',
    );
  });

  it('throws PqcError[WRONG_KEY] or DECRYPTION_FAILED when using wrong secret key', async () => {
    const keyA = await pqcKeygenTool.invoke({ algorithm: 'ml-kem-768' });
    const keyB = await pqcKeygenTool.invoke({ algorithm: 'ml-kem-768' });
    const { publicToken } = parse<{ publicToken: string }>(keyA);
    const { secretToken: wrongSecret } = parse<{ secretToken: string }>(keyB);

    const encResult = await pqcEncryptTool.invoke({ plaintext: 'secret', publicToken });
    const { ciphertextHex } = parse<{ ciphertextHex: string }>(encResult);

    await expect(
      pqcDecryptTool.invoke({ ciphertextHex, secretToken: wrongSecret }),
    ).rejects.toThrow('PqcError[');
  });
});

// ─── pqcSignTool / pqcVerifyTool ─────────────────────────────────────────────

describe('pqcSignTool / pqcVerifyTool', () => {
  it('round-trips a signature with ml-dsa-65', async () => {
    const keyResult = await pqcKeygenTool.invoke({ algorithm: 'ml-dsa-65' });
    const { publicToken, secretToken } = parse<{
      publicToken: string;
      secretToken: string;
    }>(keyResult);

    const signResult = await pqcSignTool.invoke({
      message: 'agent message v1',
      secretToken,
    });
    const { signatureHex } = parse<{ signatureHex: string }>(signResult);
    expect(signatureHex.length).toBeGreaterThan(0);

    const verifyResult = await pqcVerifyTool.invoke({
      message: 'agent message v1',
      signatureHex,
      publicToken,
    });
    const { verified } = parse<{ verified: boolean }>(verifyResult);
    expect(verified).toBe(true);
  });

  it('returns verified=false for tampered message', async () => {
    const keyResult = await pqcKeygenTool.invoke({ algorithm: 'ml-dsa-65' });
    const { publicToken, secretToken } = parse<{
      publicToken: string;
      secretToken: string;
    }>(keyResult);
    const signResult = await pqcSignTool.invoke({ message: 'original', secretToken });
    const { signatureHex } = parse<{ signatureHex: string }>(signResult);

    const verifyResult = await pqcVerifyTool.invoke({
      message: 'tampered',
      signatureHex,
      publicToken,
    });
    const { verified } = parse<{ verified: boolean }>(verifyResult);
    expect(verified).toBe(false);
  });

  it('returns verified=false for wrong public key', async () => {
    const keyA = await pqcKeygenTool.invoke({ algorithm: 'ml-dsa-65' });
    const keyB = await pqcKeygenTool.invoke({ algorithm: 'ml-dsa-65' });
    const { secretToken } = parse<{ secretToken: string }>(keyA);
    const { publicToken: wrongPub } = parse<{ publicToken: string }>(keyB);

    const signResult = await pqcSignTool.invoke({ message: 'message', secretToken });
    const { signatureHex } = parse<{ signatureHex: string }>(signResult);

    const verifyResult = await pqcVerifyTool.invoke({
      message: 'message',
      signatureHex,
      publicToken: wrongPub,
    });
    const { verified } = parse<{ verified: boolean }>(verifyResult);
    expect(verified).toBe(false);
  });
});

// ─── pqcTools bundle ─────────────────────────────────────────────────────────

describe('pqcTools', () => {
  it('contains all six tools', () => {
    expect(pqcTools).toHaveLength(6);
    const names = pqcTools.map((t) => t.name);
    expect(names).toContain('pqc_keygen');
    expect(names).toContain('pqc_encrypt');
    expect(names).toContain('pqc_decrypt');
    expect(names).toContain('pqc_sign');
    expect(names).toContain('pqc_verify');
    expect(names).toContain('pqc_algorithms');
  });

  it('all tools have a name, description and schema', () => {
    for (const t of pqcTools) {
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(t.schema).toBeDefined();
    }
  });
});
