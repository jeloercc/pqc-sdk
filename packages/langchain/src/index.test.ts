/**
 * Tests for @pqc-sdk/langchain tools.
 *
 * Tools are invoked through tool.invoke() — the LangChain invocation path —
 * with no LLM or agent runtime. This confirms:
 *   - secret keys move only through the application's callbacks, never
 *     through a schema or a tool result
 *   - keygen → encrypt → decrypt and keygen → sign → verify round trips
 *   - lossless handling of binary plaintext
 *   - structured PqcError[CODE] messages on failure
 */

import type { StructuredToolInterface } from '@langchain/core/tools';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { beforeEach, describe, expect, it } from 'vitest';

import { FIPS_ALGORITHMS, SUPPORTED_ALGORITHMS, type SecretKey, pqc } from '@pqc-sdk/core';

import {
  type CreatePqcToolsOptions,
  createPqcTools,
  pqcAlgorithmsTool,
  pqcEncryptTool,
  pqcVerifyTool,
} from './index.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

let vault: Map<string, SecretKey>;
let resolved: string[];
/** Every tool result or error message produced during a test. */
let outputs: string[];

const baseOptions = (): CreatePqcToolsOptions => ({
  resolveSecretKey: (keyId) => {
    resolved.push(keyId);
    const key = vault.get(keyId);
    return key ? Promise.resolve(key) : Promise.reject(new Error(`vault miss: ${keyId}`));
  },
  onSecretKey: (keyId, secretKey) => {
    vault.set(keyId, secretKey);
  },
});

beforeEach(() => {
  vault = new Map();
  resolved = [];
  outputs = [];
});

function byName(tools: StructuredToolInterface[], name: string): StructuredToolInterface {
  const found = tools.find((t) => t.name === name);
  if (!found) throw new Error(`tool ${name} not present`);
  return found;
}

async function invoke(
  t: StructuredToolInterface,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const result: unknown = await t.invoke(input);
  if (typeof result !== 'string') throw new Error(`Expected string, got ${typeof result}`);
  outputs.push(result);
  return JSON.parse(result) as Record<string, unknown>;
}

async function invokeError(
  t: StructuredToolInterface,
  input: Record<string, unknown>,
): Promise<string> {
  const error: unknown = await t.invoke(input).then(
    () => undefined,
    (cause: unknown) => cause,
  );
  if (!(error instanceof Error)) throw new Error('expected the tool to throw');
  outputs.push(error.message);
  return error.message;
}

async function keygen(
  tools: StructuredToolInterface[],
  algorithm: string,
): Promise<{ keyId: string; publicToken: string }> {
  return (await invoke(byName(tools, 'pqc_keygen'), { algorithm })) as {
    keyId: string;
    publicToken: string;
  };
}

// ─── tool set composition ────────────────────────────────────────────────────

describe('createPqcTools', () => {
  it('omits pqc_sign by default and includes it with enableSign', () => {
    const names = (options: CreatePqcToolsOptions) => createPqcTools(options).map((t) => t.name);
    expect(names(baseOptions())).toEqual([
      'pqc_keygen',
      'pqc_encrypt',
      'pqc_decrypt',
      'pqc_verify',
      'pqc_algorithms',
    ]);
    expect(names({ ...baseOptions(), enableSign: true })).toContain('pqc_sign');
  });

  it('omits pqc_keygen when no onSecretKey is given', () => {
    const tools = createPqcTools({ resolveSecretKey: baseOptions().resolveSecretKey });
    expect(tools.map((t) => t.name)).not.toContain('pqc_keygen');
  });

  it('no tool schema mentions a secret token', () => {
    for (const t of createPqcTools({ ...baseOptions(), enableSign: true })) {
      const serialized = JSON.stringify(t.schema);
      expect(serialized).not.toMatch(/secretToken/i);
      expect(serialized).not.toContain('.secret.');
    }
  });
});

// ─── pqcAlgorithmsTool ───────────────────────────────────────────────────────

describe('pqcAlgorithmsTool', () => {
  it('returns supported and fips arrays', async () => {
    const data = await invoke(pqcAlgorithmsTool, {});
    expect(data['supported']).toEqual([...SUPPORTED_ALGORITHMS]);
    expect(data['fips']).toEqual([...FIPS_ALGORITHMS]);
    expect(data['fips']).not.toContain('x-wing');
  });
});

// ─── pqc_keygen ──────────────────────────────────────────────────────────────

describe('pqc_keygen', () => {
  it('returns only keyId, algorithm and publicToken, handing the secret to onSecretKey', async () => {
    const tools = createPqcTools(baseOptions());
    const data = await invoke(byName(tools, 'pqc_keygen'), { algorithm: 'x-wing' });
    expect(Object.keys(data).sort()).toEqual(['algorithm', 'keyId', 'publicToken']);
    expect(data['publicToken']).toMatch(/^pqcv1\.x-wing\.public\./);
    const stored = vault.get(data['keyId'] as string);
    expect(stored?.use).toBe('secret');
    expect(stored?.algorithm).toBe('x-wing');
  });

  it('defaults to x-wing', async () => {
    const tools = createPqcTools(baseOptions());
    const data = await invoke(byName(tools, 'pqc_keygen'), {});
    expect(data['algorithm']).toBe('x-wing');
  });

  it('returns no public key when onSecretKey fails', async () => {
    const tools = createPqcTools({
      ...baseOptions(),
      onSecretKey: () => Promise.reject(new Error('storage down at /var/secret/path')),
    });
    const message = await invokeError(byName(tools, 'pqc_keygen'), { algorithm: 'x-wing' });
    expect(message).toMatch(/^PqcError\[KEY_STORAGE_FAILED\]/);
    expect(message).not.toContain('/var/secret/path');
    expect(message).not.toContain('pqcv1');
  });
});

// ─── pqc_encrypt / pqc_decrypt ───────────────────────────────────────────────

describe('pqc_encrypt / pqc_decrypt', () => {
  it.each(['ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'x-wing'])(
    'round-trips text by keyId with %s',
    async (algorithm) => {
      const tools = createPqcTools(baseOptions());
      const { keyId, publicToken } = await keygen(tools, algorithm);
      const { ciphertextHex } = await invoke(pqcEncryptTool, { publicToken, plaintext: 'hello' });
      const data = await invoke(byName(tools, 'pqc_decrypt'), { keyId, ciphertextHex });
      expect(data).toEqual({ encoding: 'utf8', plaintext: 'hello' });
      expect(resolved).toEqual([keyId]);
    },
  );

  it('round-trips non-UTF-8 bytes losslessly through base64', async () => {
    const tools = createPqcTools(baseOptions());
    const { keyId, publicToken } = await keygen(tools, 'x-wing');
    const plaintextBase64 = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0x41]).toString(
      'base64',
    );
    const { ciphertextHex } = await invoke(pqcEncryptTool, { publicToken, plaintextBase64 });
    const data = await invoke(byName(tools, 'pqc_decrypt'), { keyId, ciphertextHex });
    expect(data).toEqual({ encoding: 'base64', plaintextBase64 });
  });

  it('keeps a leading byte-order mark', async () => {
    const tools = createPqcTools(baseOptions());
    const { keyId, publicToken } = await keygen(tools, 'x-wing');
    const { ciphertextHex } = await invoke(pqcEncryptTool, { publicToken, plaintext: '﻿bom' });
    const data = await invoke(byName(tools, 'pqc_decrypt'), { keyId, ciphertextHex });
    expect(data).toEqual({ encoding: 'utf8', plaintext: '﻿bom' });
  });

  it.each([
    ['neither', {}],
    ['both', { plaintext: 'a', plaintextBase64: 'YQ==' }],
    ['invalid base64', { plaintextBase64: 'not base64!' }],
  ])('rejects %s plaintext input', async (_label, input) => {
    const pair = await pqc.keys.generate();
    const publicToken = pqc.keys.serialize(pair.publicKey);
    const message = await invokeError(pqcEncryptTool, { publicToken, ...input });
    expect(message).toMatch(/^PqcError\[INVALID_ARGUMENT\]/);
  });

  it('throws DECRYPTION_FAILED on tampered ciphertext', async () => {
    const tools = createPqcTools(baseOptions());
    const { keyId, publicToken } = await keygen(tools, 'ml-kem-768');
    const { ciphertextHex } = await invoke(pqcEncryptTool, { publicToken, plaintext: 'payload' });
    const bytes = hexToBytes(ciphertextHex as string);
    bytes[bytes.length - 1]! ^= 0xff;
    const message = await invokeError(byName(tools, 'pqc_decrypt'), {
      keyId,
      ciphertextHex: bytesToHex(bytes),
    });
    expect(message).toMatch(/^PqcError\[DECRYPTION_FAILED\]/);
  });

  it('rejects a traversal keyId before calling resolveSecretKey', async () => {
    const tools = createPqcTools(baseOptions());
    const message = await invokeError(byName(tools, 'pqc_decrypt'), {
      keyId: '../../etc/x',
      ciphertextHex: '00',
    });
    expect(message).toMatch(/^PqcError\[INVALID_ARGUMENT\]/);
    expect(message).not.toContain('etc');
    expect(resolved).toEqual([]);
  });

  it('maps a resolver failure to KEY_NOT_FOUND without leaking its message', async () => {
    const tools = createPqcTools(baseOptions());
    const message = await invokeError(byName(tools, 'pqc_decrypt'), {
      keyId: 'nobody',
      ciphertextHex: '00',
    });
    expect(message).toMatch(/^PqcError\[KEY_NOT_FOUND\]/);
    expect(message).not.toContain('vault miss');
  });

  it('rejects a resolver that returns something other than a secret key', async () => {
    const pair = await pqc.keys.generate();
    const tools = createPqcTools({
      resolveSecretKey: () => Promise.resolve(pair.publicKey as unknown as SecretKey),
    });
    const message = await invokeError(byName(tools, 'pqc_decrypt'), {
      keyId: 'k',
      ciphertextHex: '00',
    });
    expect(message).toMatch(/^PqcError\[KEY_NOT_FOUND\]/);
  });

  it('throws INVALID_CIPHERTEXT for non-hex ciphertext', async () => {
    const tools = createPqcTools(baseOptions());
    const { keyId } = await keygen(tools, 'x-wing');
    const message = await invokeError(byName(tools, 'pqc_decrypt'), { keyId, ciphertextHex: 'zz' });
    expect(message).toMatch(/^PqcError\[INVALID_CIPHERTEXT\]/);
  });
});

// ─── pqc_sign / pqc_verify ───────────────────────────────────────────────────

describe('pqc_sign / pqc_verify', () => {
  it('round-trips a signature when enabled', async () => {
    const tools = createPqcTools({ ...baseOptions(), enableSign: true });
    const { keyId, publicToken } = await keygen(tools, 'ml-dsa-65');
    const { signatureHex } = await invoke(byName(tools, 'pqc_sign'), { keyId, message: 'doc' });
    expect(await invoke(pqcVerifyTool, { message: 'doc', signatureHex, publicToken })).toEqual({
      verified: true,
    });
    expect(await invoke(pqcVerifyTool, { message: 'tampered', signatureHex, publicToken })).toEqual(
      { verified: false },
    );
  });

  it('returns verified=false for a non-hex signature', async () => {
    const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const data = await invoke(pqcVerifyTool, {
      message: 'doc',
      signatureHex: 'zz',
      publicToken: pqc.keys.serialize(signer.publicKey),
    });
    expect(data).toEqual({ verified: false });
  });

  it('throws WRONG_ALGORITHM when signing with a KEM key', async () => {
    const tools = createPqcTools({ ...baseOptions(), enableSign: true });
    const { keyId } = await keygen(tools, 'x-wing');
    const message = await invokeError(byName(tools, 'pqc_sign'), { keyId, message: 'm' });
    expect(message).toMatch(/^PqcError\[WRONG_ALGORITHM\]/);
  });
});

// ─── no secret material in any output ────────────────────────────────────────

describe('secret keys never appear in tool output', () => {
  it('holds across success and error paths of every tool', async () => {
    const tools = createPqcTools({ ...baseOptions(), enableSign: true });
    const kem = await keygen(tools, 'x-wing');
    const dsa = await keygen(tools, 'ml-dsa-65');
    const { ciphertextHex } = await invoke(pqcEncryptTool, {
      publicToken: kem.publicToken,
      plaintext: 'sweep',
    });
    await invoke(byName(tools, 'pqc_decrypt'), { keyId: kem.keyId, ciphertextHex });
    await invokeError(byName(tools, 'pqc_decrypt'), { keyId: dsa.keyId, ciphertextHex });
    await invoke(byName(tools, 'pqc_sign'), { keyId: dsa.keyId, message: 'm' });
    await invokeError(byName(tools, 'pqc_sign'), { keyId: kem.keyId, message: 'm' });

    const secrets = [...vault.values()].map((key) => pqc.keys.serialize(key).split('.')[3]!);
    expect(secrets).toHaveLength(2);
    expect(outputs.length).toBeGreaterThan(5);
    for (const text of outputs) {
      expect(text).not.toContain('.secret.');
      for (const secret of secrets) expect(text).not.toContain(secret);
    }
  });
});
