import { readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, relative } from 'node:path';

import { defineCommand } from 'citty';
import pc from 'picocolors';

import { finding, heading, note, ok } from '../ui.js';

interface Finding {
  location: string;
  what: string;
  migrateTo: string;
}

/**
 * Upper bound on the size of a single source file the scanner will read. Files
 * larger than this are skipped: they are almost never hand-written source, and
 * reading them would slow the scan with no useful signal.
 */
const MAX_FILE_BYTES = 1024 * 1024; // 1 MiB

const ML_DSA = 'ML-DSA-65 (pqc.sign / pqc.verify)';
const ML_KEM = 'ML-KEM-768 + AES-256-GCM (pqc.encrypt / pqc.decrypt)';

const RISKY_PACKAGES: Record<string, { what: string; migrateTo: string }> = {
  jsonwebtoken: { what: 'JWTs signed with RSA/ECDSA (RS256/ES256)', migrateTo: ML_DSA },
  jose: { what: 'JOSE/JWT with RSA/ECDSA algorithms', migrateTo: ML_DSA },
  elliptic: { what: 'Classic elliptic curves (ECDSA/ECDH)', migrateTo: `${ML_DSA} and ${ML_KEM}` },
  secp256k1: { what: 'ECDSA signatures over secp256k1', migrateTo: ML_DSA },
  'node-rsa': { what: 'RSA encryption and signatures', migrateTo: `${ML_KEM} and ${ML_DSA}` },
  'node-forge': { what: 'Classic RSA/X.509', migrateTo: `${ML_KEM} and ${ML_DSA}` },
  tweetnacl: { what: 'Ed25519/X25519 (pre-quantum)', migrateTo: `${ML_DSA} and ${ML_KEM}` },
};

const CODE_PATTERNS: ReadonlyArray<{ re: RegExp; what: string; migrateTo: string }> = [
  {
    re: /create(?:Sign|Verify)\s*\(/,
    what: 'RSA/ECDSA signing via node:crypto (createSign/createVerify)',
    migrateTo: ML_DSA,
  },
  {
    re: /createECDH\s*\(|\.diffieHellman\s*\(/,
    what: 'ECDH/DH key exchange',
    migrateTo: ML_KEM,
  },
  {
    re: /publicEncrypt\s*\(|privateDecrypt\s*\(/,
    what: 'RSA encryption (publicEncrypt/privateDecrypt)',
    migrateTo: ML_KEM,
  },
  {
    re: /generateKeyPair(?:Sync)?\s*\(\s*['"](?:rsa|rsa-pss|dsa|ec|ed25519|ed448|x25519|x448)['"]/,
    what: 'pre-quantum keypair generation',
    migrateTo: 'pqc.keys.generate (ML-KEM-768 for encryption, ML-DSA-65 for signatures)',
  },
  {
    re: /['"`](?:RS|ES|PS)(?:256|384|512)['"`]/,
    what: 'JWT with an RSA/ECDSA signing algorithm',
    migrateTo: ML_DSA,
  },
  {
    re: /['"`](?:RSA-OAEP|ECDH|ECDSA)['"`]/,
    what: 'WebCrypto with a pre-quantum algorithm',
    migrateTo: `${ML_KEM} or ${ML_DSA}`,
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

interface SourceScan {
  findings: Finding[];
  /** Files skipped because they exceed {@link MAX_FILE_BYTES}, relative to cwd. */
  skipped: string[];
}

async function auditSources(cwd: string): Promise<SourceScan> {
  const findings: Finding[] = [];
  const skipped: string[] = [];
  for (const file of await collectSourceFiles(cwd)) {
    if ((await stat(file)).size > MAX_FILE_BYTES) {
      skipped.push(relative(cwd, file));
      continue;
    }
    const lines = (await readFile(file, 'utf8')).split('\n');
    lines.forEach((line, index) => {
      for (const { re, what, migrateTo } of CODE_PATTERNS) {
        if (re.test(line)) {
          findings.push({ location: `${relative(cwd, file)}:${index + 1}`, what, migrateTo });
        }
      }
    });
  }
  return { findings, skipped };
}

export const audit = defineCommand({
  meta: {
    name: 'audit',
    description:
      'Heuristically detect pre-quantum crypto (best-effort regex scan) and suggest the PQC equivalent',
  },
  async run() {
    const cwd = process.cwd();
    const { findings: sourceFindings, skipped } = await auditSources(cwd);
    const findings = [...(await auditPackageJson(cwd)), ...sourceFindings];

    note(
      'Heuristic, best-effort regex scan — expect occasional false positives and false negatives.',
    );
    if (skipped.length > 0) {
      note(
        `Skipped ${skipped.length} file(s) larger than ${MAX_FILE_BYTES / 1024 / 1024} MiB: ${skipped.join(', ')}`,
      );
    }

    if (findings.length === 0) {
      ok('No pre-quantum crypto detected.');
      return;
    }

    heading(`Pre-quantum crypto detected (${findings.length} findings):`);
    for (const f of findings) {
      finding(f.location, f.what, f.migrateTo);
    }
    console.log();
    console.log(
      pc.yellow(
        `${findings.length} usages to migrate. Algorithm guide: FIPS 203 (ML-KEM) encryption, FIPS 204 (ML-DSA) signatures.`,
      ),
    );
    process.exitCode = 1;
  },
});
