/**
 * Report output: the JSON report (every run record) and a short markdown
 * summary with one table per model. Both hold counts, lengths and booleans
 * only; `assertNoSecrets` re-runs the leak canary over the rendered text
 * before anything is written.
 */

import type { SecretKey } from '@pqc-sdk/core';
import { scanForLeaks } from './canary.js';
import type { ModelReport, ScenarioSummary } from './harness.js';
import { SCENARIOS } from './scenarios.js';

export interface EvalReport {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly models: readonly ModelReport[];
  /** Models whose endpoint preflight failed; they have no runs. */
  readonly skippedModels: readonly { readonly model: string; readonly reason: string }[];
}

function pct(n: number, d: number): string {
  return d === 0 ? '–' : `${Math.round((n / d) * 100)}%`;
}

function median(values: readonly number[]): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

function missCell(s: ScenarioSummary): string {
  const misses = s.decryptCalls - s.copyExact;
  if (misses === 0) return '–';
  const med = median(s.copyMissDistances);
  const maxLen = Math.max(...s.copyMissLengthDiffs.map(Math.abs));
  return `${misses} (dist med ${med ?? 'n/a'}, max \\|Δlen\\| ${maxLen})`;
}

function row(name: string, s: ScenarioSummary): string {
  const e = s.toolErrors;
  return [
    name,
    `${s.passes}/${s.runs} (${pct(s.passes, s.runs)})`,
    s.leakHits === 0 ? '0' : `**${s.leakHits} in ${s.leakRuns} runs**`,
    `${s.copyExact}/${s.decryptCalls}`,
    missCell(s),
    String(e.schema + s.malformedToolCalls),
    String(e.invalidKeyId),
    String(e.unknownTool),
    String(s.agentErrors.recursion_limit + s.agentErrors.model_error),
    s.stepsMean.toFixed(1),
    `${s.latencyMsP50} / ${s.latencyMsP95}`,
  ].join(' | ');
}

function modelSection(m: ModelReport): string {
  const lines = [
    `## ${m.model}`,
    '',
    `${m.runsPerScenario} runs per scenario, recursion limit ${m.recursionLimit}.`,
    '',
  ];
  if (m.leakHits > 0) {
    lines.push(
      `> **SECRET KEY LEAK: ${m.leakHits} hit(s).** Secret key material appeared in the transcript. ` +
        'See `leak.locations` in the JSON report.',
      '',
    );
  }
  lines.push(
    '| Scenario | Pass | Leak hits | Exact copies | Copy misses | Schema errors | Bad keyIds | Unknown tools | Agent errors | Steps (mean) | Latency ms p50 / p95 |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  );
  for (const name of SCENARIOS) {
    const scenario = m.scenarios[name];
    if (scenario) lines.push(`| ${row(name, scenario.summary)} |`);
  }
  const inj = m.scenarios.injection?.summary.injection;
  if (inj) {
    const after = Object.entries(inj.postDecryptToolCalls)
      .map(([name, n]) => `${name}×${n}`)
      .join(', ');
    lines.push(
      '',
      `Injection: followed in ${inj.followedInjectionRuns} runs; pqc_sign attempted in ` +
        `${inj.signAttemptRuns}; encrypt-to-attacker in ${inj.exfilEncryptRuns}; keygen in ` +
        `${inj.keygenRuns}; tool calls after decrypt: ${after || 'none'}.`,
    );
  }
  return lines.join('\n');
}

export function renderMarkdown(report: EvalReport): string {
  const sections = [
    '# Open-model eval: @pqc-sdk/langchain',
    '',
    `Generated ${report.generatedAt}.`,
    '',
    ...report.models.map(modelSection).flatMap((s) => [s, '']),
  ];
  for (const skipped of report.skippedModels) {
    sections.push(`## ${skipped.model}`, '', `Skipped: ${skipped.reason}`, '');
  }
  return sections.join('\n');
}

/** Throws if any secret key appears in `text`. The thrown message names counts only. */
export function assertNoSecrets(
  text: string,
  secrets: readonly SecretKey[],
  publicKeys: readonly Uint8Array[],
): void {
  const hits = scanForLeaks([{ where: 'report', index: -1, text }], secrets, publicKeys);
  if (hits.length > 0) {
    throw new Error(
      `refusing to write a report containing secret key material (${hits.length} hit(s))`,
    );
  }
}
