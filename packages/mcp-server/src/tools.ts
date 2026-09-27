/**
 * MCP tool definitions. Kept separate from index.ts so tests can inspect the
 * schemas without starting the stdio transport.
 *
 * No schema accepts or describes secret key material: tools refer to secret
 * keys only by `keyId`, and the keys themselves stay in the server's keystore.
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';

const ALGORITHMS = [
  'ml-kem-512',
  'ml-kem-768',
  'ml-kem-1024',
  'x-wing',
  'ml-dsa-44',
  'ml-dsa-65',
  'ml-dsa-87',
];

const KEY_ID = {
  type: 'string',
  description: 'Id of a key in the server keystore, as returned by pqc_keygen or pqc_list_keys.',
};

const KEYGEN: Tool = {
  name: 'pqc_keygen',
  description:
    'Generate a post-quantum key pair and store it in the server keystore. Returns its keyId ' +
    'and publicToken (safe to share). The secret key never leaves the server. ' +
    'Use x-wing or ml-kem-768 for encryption, ml-dsa-65 for signatures.',
  inputSchema: {
    type: 'object',
    properties: {
      algorithm: {
        type: 'string',
        enum: ALGORITHMS,
        description: 'Algorithm to use. Default: x-wing.',
        default: 'x-wing',
      },
    },
    required: [],
  },
};

const LIST_KEYS: Tool = {
  name: 'pqc_list_keys',
  description:
    'List the keys in the server keystore: keyId, algorithm and publicToken for each. ' +
    'Secret keys are never returned.',
  inputSchema: { type: 'object', properties: {}, required: [] },
};

const ENCRYPT: Tool = {
  name: 'pqc_encrypt',
  description:
    'Encrypt data for a recipient using their public key token. Only the holder of the ' +
    'matching secret key can decrypt. Pass exactly one of plaintext (UTF-8 text) or ' +
    'plaintextBase64 (binary data). Quantum-resistant.',
  inputSchema: {
    type: 'object',
    properties: {
      publicToken: {
        type: 'string',
        description: "Recipient's public key token (pqcv1.*.public.*).",
      },
      plaintext: { type: 'string', description: 'Text to encrypt (UTF-8).' },
      plaintextBase64: { type: 'string', description: 'Binary data to encrypt, base64-encoded.' },
    },
    required: ['publicToken'],
  },
};

const DECRYPT: Tool = {
  name: 'pqc_decrypt',
  description:
    'Decrypt a ciphertext with a key from the server keystore. Returns ' +
    '{ encoding: "utf8", plaintext } when the data is valid UTF-8, otherwise ' +
    '{ encoding: "base64", plaintextBase64 }. Returns isError with DECRYPTION_FAILED if ' +
    'the ciphertext was tampered with or encrypted for a different key.',
  inputSchema: {
    type: 'object',
    properties: {
      keyId: KEY_ID,
      ciphertextHex: { type: 'string', description: 'Hex-encoded ciphertext from pqc_encrypt.' },
    },
    required: ['keyId', 'ciphertextHex'],
  },
};

const SIGN: Tool = {
  name: 'pqc_sign',
  description:
    'Sign a message with an ML-DSA key from the server keystore. ' +
    'Proves the message came from this key and was not modified.',
  inputSchema: {
    type: 'object',
    properties: {
      keyId: KEY_ID,
      message: { type: 'string', description: 'Message to sign (UTF-8).' },
    },
    required: ['keyId', 'message'],
  },
};

const VERIFY: Tool = {
  name: 'pqc_verify',
  description:
    'Verify an ML-DSA signature. Returns { verified: true } if genuine, ' +
    '{ verified: false } if tampered, wrong key, or wrong message.',
  inputSchema: {
    type: 'object',
    properties: {
      message: { type: 'string', description: 'Original message that was signed.' },
      signatureHex: { type: 'string', description: 'Hex-encoded signature from pqc_sign.' },
      publicToken: { type: 'string', description: "Signer's ML-DSA public key token." },
    },
    required: ['message', 'signatureHex', 'publicToken'],
  },
};

const ALGORITHMS_TOOL: Tool = {
  name: 'pqc_algorithms',
  description:
    'List all supported algorithms and the FIPS-standardized subset. ' +
    'Use this before pqc_keygen to pick the right algorithm.',
  inputSchema: { type: 'object', properties: {}, required: [] },
};

export interface ToolOptions {
  /** Whether `pqc_sign` is exposed. Off unless the operator opts in. */
  readonly enableSign: boolean;
}

/**
 * The tools this server advertises. `pqc_sign` is included only when signing
 * is enabled, so a model never sees a tool it cannot call.
 *
 * @example
 * ```ts
 * import { listTools } from './tools.js';
 *
 * const names = listTools({ enableSign: false }).map((tool) => tool.name);
 * // names does not include 'pqc_sign'
 * ```
 */
export function listTools(options: ToolOptions): Tool[] {
  return [
    KEYGEN,
    LIST_KEYS,
    ENCRYPT,
    DECRYPT,
    ...(options.enableSign ? [SIGN] : []),
    VERIFY,
    ALGORITHMS_TOOL,
  ];
}
