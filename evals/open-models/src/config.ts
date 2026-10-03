/**
 * Eval configuration, read from the environment.
 *
 * `EVAL_BASE_URL` is the switch: when it is unset the eval is skipped, so
 * nothing here ever runs in CI by accident.
 */

export interface EvalConfig {
  /** OpenAI-compatible base URL, e.g. `https://<pod>-8000.proxy.runpod.net/v1`. */
  readonly baseUrl: string;
  /** Bearer token for the endpoint. vLLM without `--api-key` accepts any value. */
  readonly apiKey: string;
  /** Served model names; `EVAL_MODEL` may list several, comma-separated. */
  readonly models: readonly string[];
  /** Runs per scenario. */
  readonly runs: number;
}

export const DEFAULT_RUNS = 10;
const MAX_RUNS = 1000;

/**
 * Returns the eval configuration, or `undefined` when `EVAL_BASE_URL` is
 * unset (the eval should be skipped). Throws on a configuration that is set
 * but invalid, so a typo never silently runs with defaults.
 */
export function readConfig(env: NodeJS.ProcessEnv = process.env): EvalConfig | undefined {
  const baseUrl = env.EVAL_BASE_URL?.trim();
  if (!baseUrl) return undefined;

  const models = (env.EVAL_MODEL ?? '')
    .split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0);
  if (models.length === 0) {
    throw new Error('EVAL_MODEL must name the served model (comma-separated for several)');
  }

  let runs = DEFAULT_RUNS;
  const rawRuns = env.EVAL_RUNS?.trim();
  if (rawRuns) {
    if (!/^\d+$/.test(rawRuns) || Number(rawRuns) < 1 || Number(rawRuns) > MAX_RUNS) {
      throw new Error(`EVAL_RUNS must be an integer from 1 to ${MAX_RUNS}`);
    }
    runs = Number(rawRuns);
  }

  return { baseUrl, apiKey: env.EVAL_API_KEY?.trim() || 'EMPTY', models, runs };
}
