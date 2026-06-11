import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, relative } from 'node:path';

import { defineCommand } from 'citty';
import pc from 'picocolors';

import { finding, heading, ok } from '../ui.js';

interface Finding {
  location: string;
  what: string;
  migrateTo: string;
}

const ML_DSA = 'ML-DSA-65 (pqc.sign / pqc.verify)';
const ML_KEM = 'ML-KEM-768 + AES-256-GCM (pqc.encrypt / pqc.decrypt)';

const RISKY_PACKAGES: Record<string, { what: string; migrateTo: string }> = {
  jsonwebtoken: { what: 'JWTs firmados con RSA/ECDSA (RS256/ES256)', migrateTo: ML_DSA },
  jose: { what: 'JOSE/JWT con algoritmos RSA/ECDSA', migrateTo: ML_DSA },
  elliptic: { what: 'Curvas elípticas clásicas (ECDSA/ECDH)', migrateTo: `${ML_DSA} y ${ML_KEM}` },
  secp256k1: { what: 'Firmas ECDSA sobre secp256k1', migrateTo: ML_DSA },
  'node-rsa': { what: 'Cifrado y firmas RSA', migrateTo: `${ML_KEM} y ${ML_DSA}` },
  'node-forge': { what: 'RSA/X.509 clásico', migrateTo: `${ML_KEM} y ${ML_DSA}` },
  tweetnacl: { what: 'Ed25519/X25519 (pre-cuántico)', migrateTo: `${ML_DSA} y ${ML_KEM}` },
};

const CODE_PATTERNS: ReadonlyArray<{ re: RegExp; what: string; migrateTo: string }> = [
  {
    re: /create(?:Sign|Verify)\s*\(/,
    what: 'firma RSA/ECDSA vía node:crypto (createSign/createVerify)',
    migrateTo: ML_DSA,
  },
  {
    re: /createECDH\s*\(|\.diffieHellman\s*\(/,
    what: 'intercambio de claves ECDH/DH',
    migrateTo: ML_KEM,
  },
  {
    re: /publicEncrypt\s*\(|privateDecrypt\s*\(/,
    what: 'cifrado RSA (publicEncrypt/privateDecrypt)',
    migrateTo: ML_KEM,
  },
  {
    re: /generateKeyPair(?:Sync)?\s*\(\s*['"](?:rsa|rsa-pss|dsa|ec|ed25519|ed448|x25519|x448)['"]/,
    what: 'generación de keypair pre-cuántico',
    migrateTo: 'pqc.keys.generate (ML-KEM-768 para cifrado, ML-DSA-65 para firmas)',
  },
  {
    re: /['"`](?:RS|ES|PS)(?:256|384|512)['"`]/,
    what: 'JWT con algoritmo de firma RSA/ECDSA',
    migrateTo: ML_DSA,
  },
  {
    re: /['"`](?:RSA-OAEP|ECDH|ECDSA)['"`]/,
    what: 'WebCrypto con algoritmo pre-cuántico',
    migrateTo: `${ML_KEM} o ${ML_DSA}`,
  },
];

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.next']);

async function collectSourceFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) pending.push(join(dir, entry.name));
        continue;
      }
      const dot = entry.name.lastIndexOf('.');
      if (dot !== -1 && SOURCE_EXTENSIONS.has(entry.name.slice(dot))) {
        files.push(join(dir, entry.name));
      }
    }
  }
  return files.sort();
}

async function auditPackageJson(cwd: string): Promise<Finding[]> {
  const path = join(cwd, 'package.json');
  if (!existsSync(path)) return [];
  const manifest = JSON.parse(await readFile(path, 'utf8')) as Record<
    string,
    Record<string, string> | undefined
  >;
  const declared = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.peerDependencies,
  };
  return Object.keys(declared)
    .filter((name) => name in RISKY_PACKAGES)
    .map((name) => ({ location: `package.json (${name})`, ...RISKY_PACKAGES[name]! }));
}

async function auditSources(cwd: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of await collectSourceFiles(cwd)) {
    const lines = (await readFile(file, 'utf8')).split('\n');
    lines.forEach((line, index) => {
      for (const { re, what, migrateTo } of CODE_PATTERNS) {
        if (re.test(line)) {
          findings.push({ location: `${relative(cwd, file)}:${index + 1}`, what, migrateTo });
        }
      }
    });
  }
  return findings;
}

export const audit = defineCommand({
  meta: {
    name: 'audit',
    description: 'Detecta crypto pre-cuántico y sugiere el equivalente PQC',
  },
  async run() {
    const cwd = process.cwd();
    const findings = [...(await auditPackageJson(cwd)), ...(await auditSources(cwd))];

    if (findings.length === 0) {
      ok('Sin crypto pre-cuántico detectado.');
      return;
    }

    heading(`Crypto pre-cuántico detectado (${findings.length} hallazgos):`);
    for (const f of findings) {
      finding(f.location, f.what, f.migrateTo);
    }
    console.log();
    console.log(
      pc.yellow(
        `${findings.length} usos a migrar. Guía de algoritmos: FIPS 203 (ML-KEM) cifrado, FIPS 204 (ML-DSA) firmas.`,
      ),
    );
    process.exitCode = 1;
  },
});
