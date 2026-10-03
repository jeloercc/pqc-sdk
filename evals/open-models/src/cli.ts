/**
 * `pnpm --filter @pqc-sdk/eval-open-models eval`
 *
 * Runs the open-model eval against EVAL_BASE_URL. See README.md.
 */

import { fileURLToPath } from 'node:url';
import { ChatOpenAI } from '@langchain/openai';
import { main } from './main.js';

const outDir = fileURLToPath(new URL('../reports', import.meta.url));

process.exitCode = await main({
  outDir,
  createModel: (config, model) =>
    Promise.resolve(
      new ChatOpenAI({
        model,
        apiKey: config.apiKey,
        configuration: { baseURL: config.baseUrl },
        // vLLM serves Chat Completions; keep LangChain off the Responses API.
        useResponsesApi: false,
        maxRetries: 1,
      }),
    ),
});
