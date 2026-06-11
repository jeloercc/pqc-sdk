import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { SUPPORTED_ALGORITHMS, pqc, type SupportedAlgorithm } from '@pqc-sdk/core';

export interface WrittenKeyPair {
  algorithm: SupportedAlgorithm;
  publicPath: string;
  secretPath: string;
}

export function assertSupportedAlgorithm(value: string): SupportedAlgorithm {
  if (!(SUPPORTED_ALGORITHMS as readonly string[]).includes(value)) {
    throw new Error(
      `Algoritmo no soportado: ${value} (soportados: ${SUPPORTED_ALGORITHMS.join(', ')})`,
    );
  }
  return value as SupportedAlgorithm;
}

/** Genera un par y lo escribe serializado en base64url, un archivo por key. */
export async function writeKeyPair(
  directory: string,
  baseName: string,
  algorithm: SupportedAlgorithm,
  force: boolean,
): Promise<WrittenKeyPair> {
  const publicPath = join(directory, `${baseName}.public.pqc`);
  const secretPath = join(directory, `${baseName}.secret.pqc`);

  if (!force) {
    for (const path of [publicPath, secretPath]) {
      if (existsSync(path)) {
        throw new Error(`${path} ya existe. Usá --force para sobreescribirla.`);
      }
    }
  }

  const pair = await pqc.keys.generate({ algorithm });
  await mkdir(directory, { recursive: true });
  await writeFile(publicPath, `${pqc.keys.serialize(pair.publicKey)}\n`);
  await writeFile(secretPath, `${pqc.keys.serialize(pair.secretKey)}\n`, { mode: 0o600 });
  await chmod(secretPath, 0o600);

  return { algorithm, publicPath, secretPath };
}
