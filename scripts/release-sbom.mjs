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
 *   0. skip it if its release `<name>@<version>` (the tag changesets
 *      creates) already has the SBOM asset, so a re-run neither fails nor
 *      uploads a duplicate;
 *   1. `pnpm pack` it, so `workspace:*` ranges are rewritten exactly as in
 *      the tarball that was published;
 *   2. wait until every @pqc-sdk/* dependency of that manifest is visible
 *      in the registry at the exact version: a sibling published seconds
 *      earlier in the same run (e.g. @pqc-sdk/core) can take minutes to
 *      appear;
 *   3. install that manifest's production dependencies with npm, the way a
 *      consumer resolves them: dev dependencies are omitted, peers are
 *      installed as npm 7+ does by default (some transitive dependencies
 *      have required peers);
 *   4. run @cyclonedx/cyclonedx-npm with the package as the main component;
 *   5. upload `<scope>-<name>-<version>.cdx.json` to that release.
 *
 * Every npm call in steps 2 and 3 uses a fresh cache and --prefer-online.
 * The registry serves packuments with `Cache-Control: max-age=300`, and npm
 * answers from its cache inside that window without asking the registry, so
 * retries against a cached packument that predates the sibling's publish
 * keep failing with ETARGET for five minutes (release run 40237918263).
 *
 * The SBOM lists npm dependencies. Code vendored into a package's own
 * source (packages/core/src/vendor/) is part of that package, not a
 * dependency, so it does not appear as a separate component.
 *
 * SBOM_DRY_RUN=1 skips every GitHub call, the release check included, and
 * the upload (local testing). SBOM_OUT_DIR sets where the files go
 * (default: sbom/ in the repo root).
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

// Exact version: the generator is part of the release pipeline.
const CYCLONEDX_NPM = '@cyclonedx/cyclonedx-npm@6.0.1';
const REGISTRY_ATTEMPTS = 30;
const REGISTRY_RETRY_MS = 20_000;
const INSTALL_ATTEMPTS = 3;
const INSTALL_RETRY_MS = 20_000;

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const outDir = resolve(process.env.SBOM_OUT_DIR ?? join(root, 'sbom'));
const dryRun = process.env.SBOM_DRY_RUN === '1';

function run(command, args, cwd) {
  execFileSync(command, args, { cwd, stdio: 'inherit' });
}

function output(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
}

function sbomFileName({ name, version }) {
  return `${name.slice(1).replace('/', '-')}-${version}.cdx.json`;
}

function releaseAssets(tag) {
  const names = output(
    'gh',
    ['release', 'view', tag, '--json', 'assets', '--jq', '.assets[].name'],
    root,
  );
  return names.split('\n').filter(Boolean);
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

// The @pqc-sdk/* dependencies of a packed manifest, as exact { name, version }.
// `pnpm pack` rewrites `workspace:*` to the sibling's exact version.
function siblingDependencies(manifest) {
  return Object.entries(manifest.dependencies ?? {})
    .filter(([name]) => name.startsWith('@pqc-sdk/'))
    .map(([name, version]) => ({ name, version }));
}

async function waitForRegistry(packages, npmFlags, cwd) {
  for (const { name, version } of packages) {
    for (let attempt = 1; ; attempt++) {
      let seen = '';
      try {
        seen = output('npm', ['view', `${name}@${version}`, 'version', ...npmFlags], cwd).trim();
      } catch {
        // Reported below like a missing version; the next attempt retries.
      }
      if (seen === version) break;
      if (attempt >= REGISTRY_ATTEMPTS) {
        throw new Error(`${name}@${version} is still not visible in the registry`);
      }
      console.error(
        `${name}@${version} is not in the registry yet (attempt ${attempt}); ` +
          `retrying in ${REGISTRY_RETRY_MS / 1000}s`,
      );
      await sleep(REGISTRY_RETRY_MS);
    }
  }
}

async function installProduction(npmFlags, cwd) {
  for (let attempt = 1; ; attempt++) {
    try {
      run(
        'npm',
        ['install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', ...npmFlags],
        cwd,
      );
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

    // A cache of its own, outside pkgDir so the SBOM does not see it, and
    // --prefer-online so no retry is answered from a stale cached packument.
    const npmFlags = ['--cache', join(work, 'npm-cache'), '--prefer-online'];
    const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
    await waitForRegistry(siblingDependencies(manifest), npmFlags, pkgDir);
    await installProduction(npmFlags, pkgDir);

    const file = join(outDir, sbomFileName({ name, version }));
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
  const tag = `${pkg.name}@${pkg.version}`;
  if (!dryRun && releaseAssets(tag).includes(sbomFileName(pkg))) {
    console.log(`SBOM: ${tag} already has ${sbomFileName(pkg)}; skipping`);
    continue;
  }
  const file = await sbomFor(pkg, workspace);
  console.log(`SBOM: ${file}`);
  if (dryRun) continue;
  run('gh', ['release', 'upload', tag, file], root);
}
