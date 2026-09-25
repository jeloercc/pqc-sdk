/**
 * Smoke tests for @pqc-sdk/mcp-server tool handlers.
 *
 * Tests call the handler function directly — no MCP stdio transport needed.
 * This verifies all six tools end-to-end: keygen, encrypt, decrypt, sign,
 * verify, and algorithms.
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { FIPS_ALGORITHMS, SUPPORTED_ALGORITHMS } from '@pqc-sdk/core';

import { handleToolForTest } from './handlers.js';

/** Safely check isError on a CallToolResult union. */
function isErr(r: CallToolResult): boolean {
  return r.isError === true;
}

/** Extract the text of the first content item. All our tools return a text item. */
function getText(r: CallToolResult): string {
  const item = r.content[0];
  if (item && item.type === 'text') return item.text;
  throw new Error('Expected text content item');
}

// ─── pqc_algorithms ──────────────────────────────────────────────────────────

describe('pqc_algorithms', () => {
  it('returns supported and fips arrays', async () => {
    const result = await handleToolForTest('pqc_algorithms');
    expect(isErr(result)).toBe(false);
    const data = JSON.parse(getText(result)) as {
      supported: string[];
      fips: string[];
    };
    expect(data.supported).toEqual([...SUPPORTED_ALGORITHMS]);
    expect(data.fips).toEqual([...FIPS_ALGORITHMS]);
    expect(data.fips).not.toContain('x-wing');
    expect(data.supported).toContain('x-wing');
  });
});

// ─── pqc_keygen ──────────────────────────────────────────────────────────────

describe('pqc_keygen', () => {
  it('generates an x-wing pair by default', async () => {
    const result = await handleToolForTest('pqc_keygen');
    expect(isErr(result)).toBe(false);
    const data = JSON.parse(getText(result)) as {
      algorithm: string;
      publicToken: string;
      secretToken: string;
    };
    expect(data.algorithm).toBe('x-wing');
    expect(data.publicToken).toMatch(/^pqcv1\.x-wing\.public\./);
    expect(data.secretToken).toMatch(/^pqcv1\.x-wing\.secret\./);
  });

  it('generates ml-kem-768 when requested', async () => {
    const result = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-768' });
    expect(isErr(result)).toBe(false);
    const data = JSON.parse(getText(result)) as { publicToken: string };
    expect(data.publicToken).toMatch(/^pqcv1\.ml-kem-768\.public\./);
  });

  // ml-kem-512 and ml-kem-1024 are added in feat/ml-kem-512-1024 — once that
  // branch merges, these tests will pass without change.
  it('returns isError for ml-kem-512 (not yet merged)', async () => {
    const result = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-512' });
    // On this branch: UNSUPPORTED_ALGORITHM. After feat/ml-kem-512-1024 merges: valid key.
    if (isErr(result)) {
      const errData = JSON.parse(getText(result)) as { error: string };
      expect(errData.error).toBe('UNSUPPORTED_ALGORITHM');
    } else {
      const data = JSON.parse(getText(result)) as { publicToken: string };
      expect(data.publicToken).toMatch(/^pqcv1\.ml-kem-512\.public\./);
    }
  });

  it('returns isError for ml-kem-1024 (not yet merged)', async () => {
    const result = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-1024' });
    if (isErr(result)) {
      const errData = JSON.parse(getText(result)) as { error: string };
      expect(errData.error).toBe('UNSUPPORTED_ALGORITHM');
    } else {
      const data = JSON.parse(getText(result)) as { publicToken: string };
      expect(data.publicToken).toMatch(/^pqcv1\.ml-kem-1024\.public\./);
    }
  });

  it('generates ml-dsa-65 when requested', async () => {
    const result = await handleToolForTest('pqc_keygen', { algorithm: 'ml-dsa-65' });
    expect(isErr(result)).toBe(false);
    const data = JSON.parse(getText(result)) as { publicToken: string };
    expect(data.publicToken).toMatch(/^pqcv1\.ml-dsa-65\.public\./);
  });

  it('returns isError for unknown algorithm', async () => {
    const result = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-9999' });
    expect(isErr(result)).toBe(true);
    const errData = JSON.parse(getText(result)) as { error: string };
    expect(errData.error).toBe('UNSUPPORTED_ALGORITHM');
  });
});

// ─── pqc_encrypt / pqc_decrypt ───────────────────────────────────────────────

describe('pqc_encrypt / pqc_decrypt', () => {
  it('round-trips a message with ml-kem-768', async () => {
    const keyResult = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-768' });
    const { publicToken, secretToken } = JSON.parse(getText(keyResult)) as {
      publicToken: string;
      secretToken: string;
    };

    const encResult = await handleToolForTest('pqc_encrypt', {
      plaintext: 'hello from agent',
      publicToken,
    });
    expect(isErr(encResult)).toBe(false);
    const { ciphertextHex } = JSON.parse(getText(encResult)) as { ciphertextHex: string };
    expect(ciphertextHex.length).toBeGreaterThan(0);

    const decResult = await handleToolForTest('pqc_decrypt', { ciphertextHex, secretToken });
    expect(isErr(decResult)).toBe(false);
    const { plaintext } = JSON.parse(getText(decResult)) as { plaintext: string };
    expect(plaintext).toBe('hello from agent');
  });

  it('round-trips a message with x-wing', async () => {
    const keyResult = await handleToolForTest('pqc_keygen', { algorithm: 'x-wing' });
    const { publicToken, secretToken } = JSON.parse(getText(keyResult)) as {
      publicToken: string;
      secretToken: string;
    };
    const encResult = await handleToolForTest('pqc_encrypt', {
      plaintext: 'x-wing msg',
      publicToken,
    });
    const { ciphertextHex } = JSON.parse(getText(encResult)) as { ciphertextHex: string };
    const decResult = await handleToolForTest('pqc_decrypt', { ciphertextHex, secretToken });
    const { plaintext } = JSON.parse(getText(decResult)) as { plaintext: string };
    expect(plaintext).toBe('x-wing msg');
  });

  it('returns isError DECRYPTION_FAILED on tampered ciphertext', async () => {
    const keyResult = await handleToolForTest('pqc_keygen', { algorithm: 'ml-kem-768' });
    const { publicToken, secretToken } = JSON.parse(getText(keyResult)) as {
      publicToken: string;
      secretToken: string;
    };
    const encResult = await handleToolForTest('pqc_encrypt', { plaintext: 'secret', publicToken });
    const { ciphertextHex } = JSON.parse(getText(encResult)) as { ciphertextHex: string };

    const bytes = hexToBytes(ciphertextHex);
    bytes[bytes.length - 1]! ^= 0xff;
    const tampered = bytesToHex(bytes);

    const result = await handleToolForTest('pqc_decrypt', { ciphertextHex: tampered, secretToken });
    expect(isErr(result)).toBe(true);
    const errData = JSON.parse(getText(result)) as { error: string };
    expect(errData.error).toBe('DECRYPTION_FAILED');
  });
});

// ─── pqc_sign / pqc_verify ───────────────────────────────────────────────────

describe('pqc_sign / pqc_verify', () => {
  it('round-trips a signature with ml-dsa-65', async () => {
    const keyResult = await handleToolForTest('pqc_keygen', { algorithm: 'ml-dsa-65' });
    const { publicToken, secretToken } = JSON.parse(getText(keyResult)) as {
      publicToken: string;
      secretToken: string;
    };

    const signResult = await handleToolForTest('pqc_sign', {
      message: 'agent message v1',
      secretToken,
    });
    expect(isErr(signResult)).toBe(false);
    const { signatureHex } = JSON.parse(getText(signResult)) as { signatureHex: string };
    expect(signatureHex.length).toBeGreaterThan(0);

    const verifyResult = await handleToolForTest('pqc_verify', {
      message: 'agent message v1',
      signatureHex,
      publicToken,
    });
    expect(isErr(verifyResult)).toBe(false);
    const { verified } = JSON.parse(getText(verifyResult)) as { verified: boolean };
    expect(verified).toBe(true);
  });

  it('returns verified=false for a tampered message', async () => {
    const keyResult = await handleToolForTest('pqc_keygen', { algorithm: 'ml-dsa-65' });
    const { publicToken, secretToken } = JSON.parse(getText(keyResult)) as {
      publicToken: string;
      secretToken: string;
    };
    const signResult = await handleToolForTest('pqc_sign', { message: 'original', secretToken });
    const { signatureHex } = JSON.parse(getText(signResult)) as { signatureHex: string };

    const verifyResult = await handleToolForTest('pqc_verify', {
      message: 'tampered',
      signatureHex,
      publicToken,
    });
    const { verified } = JSON.parse(getText(verifyResult)) as { verified: boolean };
    expect(verified).toBe(false);
  });
});

// ─── error handling ───────────────────────────────────────────────────────────

describe('error handling', () => {
  it('returns isError UNKNOWN_TOOL for unknown tool name', async () => {
    const result = await handleToolForTest('pqc_nonexistent');
    expect(isErr(result)).toBe(true);
    const errData = JSON.parse(getText(result)) as { error: string };
    expect(errData.error).toBe('UNKNOWN_TOOL');
  });
});
