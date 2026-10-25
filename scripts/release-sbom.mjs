#!/usr/bin/env node
/**
 * Generates a CycloneDX SBOM for each package a release just published and
 * attaches it to that package's GitHub release.
 *
 * Input: PUBLISHED_PACKAGES, the `publishedPackages` output of
 * changesets/action — a JSON array of { name, version }. It is read from the
 * environment and parsed as data; nothing from it reaches a shell.
 *
 * For each package:
 *   1. `pnpm pack` it, so `workspace:*` ranges are rewritten exactly as in
 *      the tarball that was published;
 *   2. install that manifest's production dependencies with npm, the way a
 *      consumer resolves them: dev dependencies are omitted, peers are
 *      installed as npm 7+ does by default (some transitive dependencies
 *      have required peers). Retried, because a just-published sibling such
 *      as @pqc-sdk/core can take a few minutes to appear in the registry;
 *   3. run @cyclonedx/cyclonedx-npm with the package as the main component;
 *   4. upload `<scope>-<name>-<version>.cdx.json` to the release
 *      `<name>@<version>` (the tag changesets creates).
 *
 * The SBOM lists npm dependencies. Code vendored into a package's own
 * source (packages/core/src/vendor/) is part of that package, not a
 * dependency, so it does not appear as a separate component.
 *
 * SBOM_DRY_RUN=1 skips the upload (local testing). SBOM_OUT_DIR sets where
 * the files go (default: sbom/ in the repo root).
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

// Exact version: the generator is part of the release pipeline.
const CYCLONEDX_NPM = '@cyclonedx/cyclonedx-npm@6.0.1';
const INSTALL_ATTEMPTS = 10;
const INSTALL_RETRY_MS = 30_000;

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const outDir = resolve(process.env.SBOM_OUT_DIR ?? join(root, 'sbom'));
const dryRun = process.env.SBOM_DRY_RUN === '1';

function run(command, args, cwd) {
  execFileSync(command, args, { cwd, stdio: 'inherit' });
}

function parsePublished(raw) {
  const parsed = JSON.parse(raw ?? '[]');
  if (!Array.isArray(parsed)) throw new Error('PUBLISHED_PACKAGES must be a JSON array');
  return parsed.map((entry) => {
    const { name, version } = entry ?? {};
    if (typeof name !== 'string' || !/^@pqc-sdk\/[a-z0-9-]+$/.test(name)) {
      throw new Error(`unexpected package name in PUBLISHED_PACKAGES: ${JSON.stringify(name)}`);
    }
    if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
      throw new Error(`unexpected version for ${name}: ${JSON.stringify(version)}`);
    }
    return { name, version };
  });
}

function workspaceDirs() {
  const dirs = new Map();
  for (const entry of readdirSync(join(root, 'packages'))) {
    try {
      const manifest = JSON.parse(
        readFileSync(join(root, 'packages', entry, 'package.json'), 'utf8'),
      );
      dirs.set(manifest.name, { dir: join(root, 'packages', entry), version: manifest.version });
    } catch {
      // Not a package directory.
    }
  }
  return dirs;
}

async function installProduction(cwd) {
  for (let attempt = 1; ; attempt++) {
    try {
      run('npm', ['install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], cwd);
      return;
    } catch (error) {
      if (attempt >= INSTALL_ATTEMPTS) throw error;
      console.error(
        `npm install failed (attempt ${attempt}); retrying in ${INSTALL_RETRY_MS / 1000}s`,
      );
      await sleep(INSTALL_RETRY_MS);
    }
  }
}

async function sbomFor({ name, version }, workspace) {
  const work = mkdtempSync(join(tmpdir(), 'pqc-sbom-'));
  try {
    run('pnpm', ['pack', '--pack-destination', work], workspace.dir);
    const tarball = readdirSync(work).find((file) => file.endsWith('.tgz'));
    if (!tarball) throw new Error(`pnpm pack produced no tarball for ${name}`);
    run('tar', ['-xzf', tarball], work);
    const pkgDir = join(work, 'package');

    await installProduction(pkgDir);

    const file = join(outDir, `${name.slice(1).replace('/', '-')}-${version}.cdx.json`);
    run(
      'npx',
      [
        '--yes',
        CYCLONEDX_NPM,
        '--omit',
        'dev',
        '--spec-version',
        '1.6',
        '--mc-type',
        'library',
        '--output-reproducible',
        '--validate',
        '--output-file',
        file,
      ],
      pkgDir,
    );
    return file;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

const published = parsePublished(process.env.PUBLISHED_PACKAGES);
if (published.length === 0) {
  console.log('No packages were published; no SBOMs to generate.');
  process.exit(0);
}

const workspaces = workspaceDirs();
mkdirSync(outDir, { recursive: true });

for (const pkg of published) {
  const workspace = workspaces.get(pkg.name);
  if (!workspace) throw new Error(`${pkg.name} is not a package under packages/`);
  if (workspace.version !== pkg.version) {
    throw new Error(
      `${pkg.name}: workspace is at ${workspace.version}, release says ${pkg.version}`,
    );
  }
  const file = await sbomFor(pkg, workspace);
  console.log(`SBOM: ${file}`);
  if (dryRun) continue;
  run('gh', ['release', 'upload', `${pkg.name}@${pkg.version}`, file, '--clobber'], root);
}
