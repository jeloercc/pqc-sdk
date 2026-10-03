/**
 * CLI entry logic: read the config, check each model's endpoint, run the
 * scenarios, write `reports/<timestamp>.json` and `.md`.
 *
 * Exit codes: 0 done (or skipped: `EVAL_BASE_URL` unset), 1 configuration or
 * endpoint error, 2 a secret-key leak was detected.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { SecretKey } from '@pqc-sdk/core';
import { pqcAlgorithmsTool } from '@pqc-sdk/langchain';
import { readConfig, type EvalConfig } from './config.js';
import { runModelEval, type ModelReport, type RunRecord } from './harness.js';
import { assertNoSecrets, renderMarkdown, type EvalReport } from './report.js';
import type { Vault } from './vault.js';

export interface MainDeps {
  readonly env?: NodeJS.ProcessEnv;
  /** Builds the chat model for a served model name. */
  readonly createModel: (config: EvalConfig, model: string) => Promise<BaseChatModel>;
  readonly outDir: string;
  readonly log?: (line: string) => void;
  /** Test seam, passed to the harness. */
  readonly createVault?: () => Vault;
}

function describeRun(model: string, r: RunRecord): string {
  const leak = r.leak.hits > 0 ? ` LEAK×${r.leak.hits}` : '';
  const error = r.agentError ? ` ${r.agentError}` : '';
  return `[${model}] ${r.scenario} #${r.run}: ${r.pass ? 'pass' : 'FAIL'} (${r.steps} steps, ${r.latencyMs} ms)${error}${leak}`;
}

/**
 * One tool-bound call before any key exists, so endpoint problems (tool
 * calling not enabled, wrong model name) surface with the server's own
 * message, which cannot contain key material at this point.
 */
async function preflight(model: BaseChatModel): Promise<string | undefined> {
  if (!model.bindTools) return 'the chat model does not support tool binding';
  try {
    const reply = await model
      .bindTools([pqcAlgorithmsTool])
      .invoke('Call the pqc_algorithms tool now.');
    const calls = (reply as { tool_calls?: unknown[] }).tool_calls ?? [];
    return calls.length > 0 ? undefined : 'no tool call in the preflight reply (continuing anyway)';
  } catch (error) {
    throw new Error(
      `endpoint preflight failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function main(deps: MainDeps): Promise<number> {
  const log = deps.log ?? ((line: string) => console.error(line));
  let config: EvalConfig | undefined;
  try {
    config = readConfig(deps.env ?? process.env);
  } catch (error) {
    log(`Invalid eval configuration: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
  if (!config) {
    log('EVAL_BASE_URL is not set; skipping the open-model eval.');
    return 0;
  }

  const models: ModelReport[] = [];
  const skippedModels: { model: string; reason: string }[] = [];
  const secrets: SecretKey[] = [];
  const publicKeys: Uint8Array[] = [];

  for (const name of config.models) {
    const model = await deps.createModel(config, name);
    try {
      const warning = await preflight(model);
      if (warning) log(`[${name}] warning: ${warning}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      log(`[${name}] ${reason}`);
      skippedModels.push({ model: name, reason: 'endpoint preflight failed' });
      continue;
    }
    const result = await runModelEval({
      model,
      modelName: name,
      runs: config.runs,
      onRun: (r) => log(describeRun(name, r)),
      ...(deps.createVault ? { createVault: deps.createVault } : {}),
    });
    models.push(result.report);
    secrets.push(...result.secrets);
    publicKeys.push(...result.publicKeys);
  }

  const report: EvalReport = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    models,
    skippedModels,
  };
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const markdown = renderMarkdown(report);
  assertNoSecrets(json + markdown, secrets, publicKeys);

  await mkdir(deps.outDir, { recursive: true });
  const stamp = report.generatedAt.replace(/[:.]/g, '-');
  const jsonPath = join(deps.outDir, `${stamp}.json`);
  const mdPath = join(deps.outDir, `${stamp}.md`);
  await writeFile(jsonPath, json);
  await writeFile(mdPath, markdown);
  log(`Report: ${jsonPath}`);
  log(`Summary: ${mdPath}`);

  const leakHits = models.reduce((n, m) => n + m.leakHits, 0);
  if (leakHits > 0) {
    log('');
    log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    log(`!! SECRET KEY LEAK DETECTED: ${leakHits} hit(s). This is a FAIL.`);
    log('!! Secret key material reached the model context. See leak.locations.');
    log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    return 2;
  }
  if (models.length === 0) return 1;
  return 0;
}
