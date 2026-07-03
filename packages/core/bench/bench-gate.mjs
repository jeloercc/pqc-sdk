#!/usr/bin/env node
/**
 * Performance regression gate for the vitest bench results.
 *
 * Commands:
 *   node bench-gate.mjs check    --results <file> --baseline <file> [--max-ratio 2.5]
 *   node bench-gate.mjs snapshot --results <file> --out <file>
 *
 * `check` compares each benchmark's mean against the committed baseline and
 * exits 1 when any operation is more than --max-ratio times slower, when the
 * benchmark sets differ, or when the baseline is missing. `snapshot` converts
 * a results file into a committable baseline (run it on the CI runner only —
 * see README.md in this directory).
 */

import console from 'node:console';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import process from 'node:process';

const DEFAULT_MAX_RATIO = 2.5;

function fail(message) {
  console.error(`bench-gate: ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    const value = rest[i + 1];
    if (!key?.startsWith('--') || value === undefined) {
      fail(`invalid arguments near "${key ?? ''}" — expected --flag value pairs.`);
    }
    options[key.slice(2)] = value;
  }
  return { command, options };
}

function readJson(path, what) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    fail(`${what} at ${path} is not valid JSON.`);
  }
}

/** Flatten vitest bench output into { "group > bench": { mean, rme } }. */
function extractBenchmarks(results, path) {
  const out = {};
  if (!Array.isArray(results?.files)) {
    fail(`unexpected results format in ${path} — expected vitest --outputJson content.`);
  }
  for (const file of results.files) {
    for (const group of file.groups ?? []) {
      // fullName is "src/pqc.bench.ts > ml-kem-768"; drop the file segment so
      // keys stay stable if the bench file is ever moved or renamed.
      const groupName = String(group.fullName ?? '')
        .split(' > ')
        .filter((part) => !part.includes(basename(file.filepath ?? '')))
        .join(' > ');
      for (const benchmark of group.benchmarks ?? []) {
        if (typeof benchmark.mean !== 'number') {
          fail(`benchmark "${benchmark.name}" in ${path} has no numeric mean.`);
        }
        out[`${groupName} > ${benchmark.name}`] = { mean: benchmark.mean, rme: benchmark.rme };
      }
    }
  }
  if (Object.keys(out).length === 0) {
    fail(`no benchmarks found in ${path}.`);
  }
  return out;
}

function formatRow(cells) {
  return `| ${cells.join(' | ')} |`;
}

function check(options) {
  const resultsPath = options.results ?? fail('check requires --results <file>.');
  const baselinePath = options.baseline ?? fail('check requires --baseline <file>.');
  const maxRatio = Number(options['max-ratio'] ?? DEFAULT_MAX_RATIO);
  if (!Number.isFinite(maxRatio) || maxRatio <= 1) {
    fail(`--max-ratio must be a number greater than 1, got "${options['max-ratio']}".`);
  }

  const results = readJson(resultsPath, 'results');
  if (results === null) {
    fail(`results file not found at ${resultsPath} — run \`pnpm bench\` first.`);
  }
  const current = extractBenchmarks(results, resultsPath);

  const baseline = readJson(baselinePath, 'baseline');
  if (baseline === null) {
    fail(
      `no baseline found at ${baselinePath}. Generate one on the CI runner with the ` +
        `"Bench baseline" workflow and commit it — see packages/core/bench/README.md. ` +
        `Never generate the baseline locally: means from other hardware are not comparable.`,
    );
  }
  if (typeof baseline.benchmarks !== 'object' || baseline.benchmarks === null) {
    fail(`baseline at ${baselinePath} has no "benchmarks" object.`);
  }

  const currentKeys = Object.keys(current).sort();
  const baselineKeys = Object.keys(baseline.benchmarks).sort();
  const missing = baselineKeys.filter((k) => !currentKeys.includes(k));
  const extra = currentKeys.filter((k) => !baselineKeys.includes(k));
  if (missing.length > 0 || extra.length > 0) {
    fail(
      `benchmark set differs from the baseline (missing: [${missing.join(', ')}], ` +
        `new: [${extra.join(', ')}]). Refresh the baseline in this PR — see bench/README.md.`,
    );
  }

  const rows = [
    formatRow(['Operation', 'Baseline mean', 'Current mean', 'Ratio', 'Status']),
    formatRow(['---', '---', '---', '---', '---']),
  ];
  const regressions = [];
  for (const key of baselineKeys) {
    const base = baseline.benchmarks[key].mean;
    const now = current[key].mean;
    const ratio = now / base;
    const status = ratio > maxRatio ? `❌ > ${maxRatio}x` : '✅';
    if (ratio > maxRatio)
      regressions.push(
        `${key}: ${now.toFixed(3)} ms vs ${base.toFixed(3)} ms (${ratio.toFixed(2)}x)`,
      );
    rows.push(
      formatRow([
        key,
        `${base.toFixed(3)} ms`,
        `${now.toFixed(3)} ms`,
        `${ratio.toFixed(2)}x`,
        status,
      ]),
    );
  }

  const table = [
    `### Benchmark regression check (fail above ${maxRatio}x baseline)`,
    '',
    `Baseline: ${baseline.commit ?? 'unknown commit'} · ${baseline.runner ?? 'unknown runner'} · Node ${baseline.node ?? '?'} · ${baseline.generatedAt ?? '?'}`,
    '',
    ...rows,
    '',
  ].join('\n');

  console.log(table);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${table}\n`);
  }

  if (regressions.length > 0) {
    fail(`performance regression detected:\n  ${regressions.join('\n  ')}`);
  }
  console.log('bench-gate: all operations within threshold.');
}

function snapshot(options) {
  const resultsPath = options.results ?? fail('snapshot requires --results <file>.');
  const outPath = options.out ?? fail('snapshot requires --out <file>.');

  const results = readJson(resultsPath, 'results');
  if (results === null) {
    fail(`results file not found at ${resultsPath} — run \`pnpm bench\` first.`);
  }
  const current = extractBenchmarks(results, resultsPath);

  const baseline = {
    generatedAt: new Date().toISOString(),
    commit: process.env.GITHUB_SHA ?? 'unknown',
    runner: process.env.ImageOS ?? process.env.RUNNER_OS ?? 'unknown',
    node: process.versions.node,
    benchmarks: Object.fromEntries(
      Object.entries(current).map(([key, value]) => [key, { mean: Number(value.mean.toFixed(4)) }]),
    ),
  };
  writeFileSync(outPath, `${JSON.stringify(baseline, null, 2)}\n`);
  console.log(
    `bench-gate: baseline written to ${outPath} (${Object.keys(current).length} benchmarks).`,
  );
}

const { command, options } = parseArgs(process.argv.slice(2));
if (command === 'check') check(options);
else if (command === 'snapshot') snapshot(options);
else fail(`unknown command "${command ?? ''}" — use "check" or "snapshot".`);
