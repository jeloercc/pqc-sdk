/**
 * Tool handler tests: every tool end to end against a real FileKeyStore in a
 * temp directory, plus the guarantees that secret keys never appear in a
 * schema or a tool result.
 */

import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FIPS_ALGORITHMS, SUPPORTED_ALGORITHMS } from '@pqc-sdk/core';

import { type HandlerContext, handleTool } from './handlers.js';
import { FileKeyStore } from './keystore.js';
import { listTools } from './tools.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

let root: string;
let context: HandlerContext;
let signingContext: HandlerContext;
/** Every tool result text produced during a test, for the no-secret sweep. */
let outputs: string[];

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'pqc-mcp-handlers-'));
  const keyStore = new FileKeyStore(join(root, 'keys'), { warn: () => undefined });
  context = { keyStore, enableSign: false };
  signingContext = { keyStore, enableSign: true };
  outputs = [];
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function getText(r: CallToolResult): string {
  const item = r.content[0];
  if (item && item.type === 'text') return item.text;
  throw new Error('Expected text content item');
}

async function call(
  name: string,
  args: Record<string, unknown> = {},
  ctx: HandlerContext = context,
): Promise<{ isError: boolean; data: Record<string, unknown> }> {
  const result = await handleTool(name, args, ctx);
  const text = getText(result);
  outputs.push(text);
  return { isError: result.isError === true, data: JSON.parse(text) as Record<string, unknown> };
}

async function keygen(algorithm: string): Promise<{ keyId: string; publicToken: string }> {
  const { isError, data } = await call('pqc_keygen', { algorithm });
  expect(isError).toBe(false);
  return data as { keyId: string; publicToken: string };
}

async function encryptText(publicToken: string, plaintext: string): Promise<string> {
  const { data } = await call('pqc_encrypt', { publicToken, plaintext });
  return data['ciphertextHex'] as string;
}

// ─── schemas ─────────────────────────────────────────────────────────────────

describe('tool schemas', () => {
  it.each([false, true])('never mention secret tokens (enableSign=%s)', (enableSign) => {
    const serialized = JSON.stringify(listTools({ enableSign }));
    expect(serialized).not.toMatch(/secretToken/i);
    expect(serialized).not.toContain('.secret.');
  });

  it('hides pqc_sign unless signing is enabled', () => {
    const names = (enableSign: boolean) => listTools({ enableSign }).map((tool) => tool.name);
    expect(names(false)).not.toContain('pqc_sign');
    expect(names(true)).toContain('pqc_sign');
    expect(names(false)).toEqual([
      'pqc_keygen',
      'pqc_list_keys',
      'pqc_encrypt',
      'pqc_decrypt',
      'pqc_verify',
      'pqc_algorithms',
    ]);
  });
});

// ─── pqc_algorithms ──────────────────────────────────────────────────────────

describe('pqc_algorithms', () => {
  it('returns supported and fips arrays', async () => {
    const { data } = await call('pqc_algorithms');
    expect(data['supported']).toEqual([...SUPPORTED_ALGORITHMS]);
    expect(data['fips']).toEqual([...FIPS_ALGORITHMS]);
    expect(data['fips']).not.toContain('x-wing');
  });
});

// ─── pqc_keygen / pqc_list_keys ──────────────────────────────────────────────

describe('pqc_keygen', () => {
  it('returns only keyId, algorithm and publicToken (x-wing by default)', async () => {
    const { isError, data } = await call('pqc_keygen');
    expect(isError).toBe(false);
    expect(Object.keys(data).sort()).toEqual(['algorithm', 'keyId', 'publicToken']);
    expect(data['algorithm']).toBe('x-wing');
    expect(data['publicToken']).toMatch(/^pqcv1\.x-wing\.public\./);
  });

  it.each(SUPPORTED_ALGORITHMS)('generates %s', async (algorithm) => {
    const { publicToken } = await keygen(algorithm);
    expect(publicToken.startsWith(`pqcv1.${algorithm}.public.`)).toBe(true);
  });

  it('rejects an unknown algorithm with UNSUPPORTED_ALGORITHM', async () => {
    const { isError, data } = await call('pqc_keygen', { algorithm: 'ml-kem-9999' });
    expect(isError).toBe(true);
    expect(data['error']).toBe('UNSUPPORTED_ALGORITHM');
  });

  it('rejects a non-string algorithm with INVALID_ARGUMENT', async () => {
    const { data } = await call('pqc_keygen', { algorithm: 768 });
    expect(data['error']).toBe('INVALID_ARGUMENT');
  });
});

describe('pqc_keygen cap', () => {
  it('returns KEYSTORE_FULL once the keystore holds maxKeys keys', async () => {
    const capped: HandlerContext = {
      keyStore: new FileKeyStore(join(root, 'capped'), { warn: () => undefined, maxKeys: 1 }),
      enableSign: false,
    };
    expect((await call('pqc_keygen', {}, capped)).isError).toBe(false);
    const { isError, data } = await call('pqc_keygen', {}, capped);
    expect(isError).toBe(true);
    expect(data['error']).toBe('KEYSTORE_FULL');
  });
});

describe('pqc_list_keys', () => {
  it('lists generated keys with their public tokens', async () => {
    const a = await keygen('x-wing');
    const b = await keygen('ml-dsa-65');
    const { data } = await call('pqc_list_keys');
    const keys = data['keys'] as { keyId: string; algorithm: string; publicToken: string }[];
    expect(keys.map((key) => key.keyId).sort()).toEqual([a.keyId, b.keyId].sort());
    expect(keys.find((key) => key.keyId === a.keyId)?.publicToken).toBe(a.publicToken);
  });
});

// ─── pqc_encrypt / pqc_decrypt ───────────────────────────────────────────────

describe('pqc_encrypt / pqc_decrypt', () => {
  it.each(['ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'x-wing'])(
    'round-trips text by keyId with %s',
    async (algorithm) => {
      const { keyId, publicToken } = await keygen(algorithm);
      const ciphertextHex = await encryptText(publicToken, 'hello from agent');
      const { isError, data } = await call('pqc_decrypt', { keyId, ciphertextHex });
      expect(isError).toBe(false);
      expect(data).toEqual({ encoding: 'utf8', plaintext: 'hello from agent' });
    },
  );

  it('round-trips non-UTF-8 bytes losslessly through base64', async () => {
    const { keyId, publicToken } = await keygen('x-wing');
    const binary = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0x41]);
    const plaintextBase64 = Buffer.from(binary).toString('base64');
    const { data: enc } = await call('pqc_encrypt', { publicToken, plaintextBase64 });
    const { isError, data } = await call('pqc_decrypt', {
      keyId,
      ciphertextHex: enc['ciphertextHex'],
    });
    expect(isError).toBe(false);
    expect(data).toEqual({ encoding: 'base64', plaintextBase64 });
  });

  it('returns valid UTF-8 sent as base64 as text, byte for byte', async () => {
    const { keyId, publicToken } = await keygen('x-wing');
    const { data: enc } = await call('pqc_encrypt', {
      publicToken,
      plaintextBase64: Buffer.from('héllo').toString('base64'),
    });
    const { data } = await call('pqc_decrypt', { keyId, ciphertextHex: enc['ciphertextHex'] });
    expect(data).toEqual({ encoding: 'utf8', plaintext: 'héllo' });
  });

  it('keeps a leading byte-order mark', async () => {
    const { keyId, publicToken } = await keygen('x-wing');
    const ciphertextHex = await encryptText(publicToken, '﻿bom');
    const { data } = await call('pqc_decrypt', { keyId, ciphertextHex });
    expect(data).toEqual({ encoding: 'utf8', plaintext: '﻿bom' });
  });

  it.each([
    ['neither', {}],
    ['both', { plaintext: 'a', plaintextBase64: 'YQ==' }],
    ['invalid base64', { plaintextBase64: 'not base64!' }],
  ])('rejects %s plaintext input with INVALID_ARGUMENT', async (_label, input) => {
    const { publicToken } = await keygen('x-wing');
    const { isError, data } = await call('pqc_encrypt', { publicToken, ...input });
    expect(isError).toBe(true);
    expect(data['error']).toBe('INVALID_ARGUMENT');
  });

  it('returns DECRYPTION_FAILED on tampered ciphertext', async () => {
    const { keyId, publicToken } = await keygen('ml-kem-768');
    const bytes = hexToBytes(await encryptText(publicToken, 'payload'));
    bytes[bytes.length - 1]! ^= 0xff;
    const { data } = await call('pqc_decrypt', { keyId, ciphertextHex: bytesToHex(bytes) });
    expect(data['error']).toBe('DECRYPTION_FAILED');
  });

  it('returns INVALID_CIPHERTEXT for non-hex ciphertext', async () => {
    const { keyId } = await keygen('x-wing');
    const { data } = await call('pqc_decrypt', { keyId, ciphertextHex: 'zz' });
    expect(data['error']).toBe('INVALID_CIPHERTEXT');
  });

  it('returns KEY_NOT_FOUND for an unknown keyId', async () => {
    const { data } = await call('pqc_decrypt', { keyId: 'nobody', ciphertextHex: '00' });
    expect(data['error']).toBe('KEY_NOT_FOUND');
  });

  it('rejects a traversal keyId without echoing it', async () => {
    const { data } = await call('pqc_decrypt', { keyId: '../../etc/x', ciphertextHex: '00' });
    expect(data['error']).toBe('INVALID_ARGUMENT');
    expect(data['message']).not.toContain('etc');
  });

  it('returns WRONG_ALGORITHM when decrypting with a signing key', async () => {
    const { keyId } = await keygen('ml-dsa-65');
    const { publicToken } = await keygen('x-wing');
    const ciphertextHex = await encryptText(publicToken, 'x');
    const { data } = await call('pqc_decrypt', { keyId, ciphertextHex });
    expect(data['error']).toBe('WRONG_ALGORITHM');
  });

  it.each([
    ['pqc_decrypt', {}],
    ['pqc_decrypt', { keyId: 'k' }],
    ['pqc_encrypt', { plaintext: 'x' }],
    ['pqc_verify', { message: 'm' }],
  ])('%s with missing arguments %j returns INVALID_ARGUMENT', async (name, args) => {
    const { isError, data } = await call(name, args);
    expect(isError).toBe(true);
    expect(data['error']).toBe('INVALID_ARGUMENT');
  });
});

// ─── pqc_sign / pqc_verify ───────────────────────────────────────────────────

describe('pqc_sign / pqc_verify', () => {
  it('is disabled by default', async () => {
    const { keyId } = await keygen('ml-dsa-65');
    const { isError, data } = await call('pqc_sign', { keyId, message: 'm' });
    expect(isError).toBe(true);
    expect(data['error']).toBe('TOOL_DISABLED');
  });

  it('round-trips a signature when enabled', async () => {
    const { keyId, publicToken } = await keygen('ml-dsa-65');
    const { data: sig } = await call(
      'pqc_sign',
      { keyId, message: 'agent message v1' },
      signingContext,
    );
    const signatureHex = sig['signatureHex'] as string;
    expect(
      (await call('pqc_verify', { message: 'agent message v1', signatureHex, publicToken })).data,
    ).toEqual({
      verified: true,
    });
    expect(
      (await call('pqc_verify', { message: 'tampered', signatureHex, publicToken })).data,
    ).toEqual({
      verified: false,
    });
  });

  it('returns WRONG_ALGORITHM when signing with a KEM key', async () => {
    const { keyId } = await keygen('x-wing');
    const { data } = await call('pqc_sign', { keyId, message: 'm' }, signingContext);
    expect(data['error']).toBe('WRONG_ALGORITHM');
  });

  it('returns verified=false for a non-hex signature', async () => {
    const { publicToken } = await keygen('ml-dsa-65');
    const { isError, data } = await call('pqc_verify', {
      message: 'm',
      signatureHex: 'zz',
      publicToken,
    });
    expect(isError).toBe(false);
    expect(data).toEqual({ verified: false });
  });
});

// ─── error handling ──────────────────────────────────────────────────────────

describe('error handling', () => {
  it('returns UNKNOWN_TOOL for an unknown tool name', async () => {
    const { data } = await call('pqc_nonexistent');
    expect(data['error']).toBe('UNKNOWN_TOOL');
  });
});

// ─── no secret material in any output ────────────────────────────────────────

describe('secret keys never appear in tool output', () => {
  it('holds across success and error paths of every tool', async () => {
    const kem = await keygen('x-wing');
    const dsa = await keygen('ml-dsa-65');
    const ciphertextHex = await encryptText(kem.publicToken, 'sweep');
    await call('pqc_list_keys');
    await call('pqc_decrypt', { keyId: kem.keyId, ciphertextHex });
    await call('pqc_decrypt', { keyId: dsa.keyId, ciphertextHex });
    await call('pqc_decrypt', {
      keyId: kem.keyId,
      ciphertextHex: `${ciphertextHex.slice(0, -2)}00`,
    });
    await call('pqc_sign', { keyId: dsa.keyId, message: 'm' });
    await call('pqc_sign', { keyId: dsa.keyId, message: 'm' }, signingContext);
    await call('pqc_sign', { keyId: kem.keyId, message: 'm' }, signingContext);
    await call('pqc_encrypt', { publicToken: 'pqcv1.x-wing.secret.AAAA', plaintext: 'x' });

    // The secret tokens as stored on disk: none of them, nor their encoded
    // key bytes, may appear in anything returned to the model.
    const keyDir = join(root, 'keys');
    const secretFiles = (await readdir(keyDir)).filter((name) => name.endsWith('.secret.pqc'));
    expect(secretFiles).toHaveLength(2);
    const secrets = await Promise.all(
      secretFiles.map(async (name) => (await readFile(join(keyDir, name), 'utf8')).trim()),
    );

    expect(outputs.length).toBeGreaterThan(8);
    for (const text of outputs) {
      expect(text).not.toContain('.secret.');
      for (const secret of secrets) {
        expect(text).not.toContain(secret.split('.')[3]);
      }
    }
  });
});
