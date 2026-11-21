import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  PolicyError,
  assertAssociatedCommit,
  assertAuthorship,
  inspectPullRequest,
  policyDigest,
  policyStatusDescription,
  requirePolicy,
  validateApiPath,
  validatePolicy,
} from './check-contributor-policy.mjs';

export function createGhClient({ exec = execFileSync } = {}) {
  return async (path, { method = 'GET', body } = {}) => {
    validateApiPath(path);
    requirePolicy(
      method === 'GET' ||
        (method === 'PUT' && /^repos\/[^/]+\/[^/]+\/pulls\/[1-9][0-9]*\/merge$/.test(path)),
      'INVALID_API_PATH',
    );
    const args = ['api', '--hostname', 'github.com', '--method', method, path];
    if (body) args.push('--input', '-');
    try {
      return JSON.parse(
        exec('gh', args, {
          encoding: 'utf8',
          timeout: 30000,
          maxBuffer: 16 * 1024 * 1024,
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1' },
          ...(body ? { input: JSON.stringify(body) } : {}),
        }),
      );
    } catch {
      throw new PolicyError('API_ERROR');
    }
  };
}

async function statusList(api, prefix, head) {
  const statuses = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await api(`${prefix}/commits/${head}/statuses?per_page=100&page=${page}`);
    requirePolicy(Array.isArray(batch) && batch.length <= 100, 'CHECKS_INCOMPLETE');
    statuses.push(...batch);
    if (batch.length < 100) return statuses;
  }
  throw new PolicyError('CHECKS_INCOMPLETE');
}

async function checkList(api, prefix, head) {
  const checks = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await api(
      `${prefix}/commits/${head}/check-runs?filter=latest&per_page=100&page=${page}`,
    );
    requirePolicy(
      Number.isSafeInteger(batch.total_count) &&
        batch.total_count >= 0 &&
        batch.total_count <= 1000 &&
        Array.isArray(batch.check_runs) &&
        batch.check_runs.length <= 100,
      'CHECKS_INCOMPLETE',
    );
    checks.push(...batch.check_runs);
    if (checks.length === batch.total_count) return checks;
    requirePolicy(
      batch.check_runs.length === 100 && checks.length < batch.total_count,
      'CHECKS_INCOMPLETE',
    );
  }
  throw new PolicyError('CHECKS_INCOMPLETE');
}

export async function assessMerge(api, policy, expected) {
  validatePolicy(policy);
  requirePolicy((await api('user')).id === policy.owner.id, 'MERGER_NOT_ALLOWED');
  const snapshot = await inspectPullRequest(api, policy, expected);
  requirePolicy(
    snapshot.pr.mergeable === true && snapshot.pr.mergeable_state === 'clean',
    'MERGE_NOT_READY',
  );
  const prefix = `repos/${policy.repository}`;
  const checks = await checkList(api, prefix, snapshot.head);
  requirePolicy(
    checks.length > 0 &&
      checks.every(
        (c) =>
          c.status === 'completed' &&
          c.conclusion === 'success' &&
          (!c.head_sha || c.head_sha === snapshot.head),
      ),
    'CHECKS_NOT_SUCCESSFUL',
  );
  for (const name of policy.requiredChecks)
    requirePolicy(
      checks.some((c) => c.name === name && c.app?.id === policy.actionsAppId),
      'CHECKS_NOT_SUCCESSFUL',
    );
  const latest = new Map();
  for (const status of await statusList(api, prefix, snapshot.head)) {
    requirePolicy(
      typeof status.context === 'string' && (!status.sha || status.sha === snapshot.head),
      'CHECKS_INCOMPLETE',
    );
    if (!latest.has(status.context)) latest.set(status.context, status);
  }
  requirePolicy(
    [...latest.values()].every((s) => s.state === 'success'),
    'CHECKS_NOT_SUCCESSFUL',
  );
  const status = latest.get(policy.context);
  requirePolicy(
    status?.state === 'success' &&
      status.creator?.id === policy.statusCreatorId &&
      status.description === policyStatusDescription(snapshot.base, policyDigest(policy)),
    'UNTRUSTED_POLICY_STATUS',
  );
  const urlPrefix = `https://github.com/${policy.repository}/actions/runs/`;
  const runId =
    typeof status.target_url === 'string' && status.target_url.startsWith(urlPrefix)
      ? status.target_url.slice(urlPrefix.length)
      : '';
  requirePolicy(/^[1-9][0-9]*$/.test(runId), 'UNTRUSTED_POLICY_STATUS');
  const run = await api(`${prefix}/actions/runs/${runId}`);
  requirePolicy(
    String(run.id) === runId &&
      run.path === '.github/workflows/attribution-policy.yml' &&
      run.event === 'pull_request_target' &&
      run.head_sha === snapshot.base &&
      run.head_branch === policy.baseBranch &&
      run.status === 'completed' &&
      run.conclusion === 'success',
    'UNTRUSTED_POLICY_STATUS',
  );
  return snapshot;
}

export async function mergeReviewedPr(api, policy, expected) {
  const snapshot = await assessMerge(api, policy, expected);
  const summary = {
    number: snapshot.number,
    head: snapshot.head,
    base: snapshot.base,
    tree: snapshot.tree,
  };
  if (expected.apply !== true) return { state: 'dry-run', ...summary };
  // Revalidate mutable PR metadata and the current base immediately before the mutation.
  await inspectPullRequest(api, policy, expected);
  const title = snapshot.pr.title ?? `chore: integrate reviewed changes (#${snapshot.number})`;
  requirePolicy(
    typeof title === 'string' && title.length > 0 && title.length <= 200 && !/[\r\n\0]/.test(title),
    'INVALID_MERGE_MESSAGE',
  );
  const message = `Reviewed owner-authored changes from PR #${snapshot.number}.\n\nValidated head: ${snapshot.head}\nValidated base: ${snapshot.base}\nOwner attribution and all reported checks passed before integration.\n`;
  assertAuthorship(
    {
      name: policy.owner.names[0],
      email: policy.owner.emails[0],
      message: title + '\n\n' + message,
    },
    policy,
  );
  const merged = await api(`repos/${policy.repository}/pulls/${snapshot.number}/merge`, {
    method: 'PUT',
    body: {
      sha: snapshot.head,
      merge_method: 'squash',
      commit_title: title,
      commit_message: message,
    },
  });
  requirePolicy(merged.merged === true && /^[a-f0-9]{40}$/.test(merged.sha), 'MERGE_REJECTED');
  try {
    const commit = await api(`repos/${policy.repository}/commits/${merged.sha}`);
    assertAssociatedCommit(commit, policy, merged.sha);
    requirePolicy(commit.commit.tree?.sha === snapshot.tree, 'TREE_MISMATCH');
    requirePolicy(
      commit.parents?.length === 1 && commit.parents[0].sha === snapshot.base,
      'BASE_CHANGED',
    );
  } catch (error) {
    const safe = error instanceof PolicyError ? error : new PolicyError('API_ERROR');
    safe.mergeSha = merged.sha;
    throw safe;
  }
  return { state: 'merged', ...summary, sha: merged.sha, author: policy.owner.login };
}

export function parseMergeArguments(args) {
  const parsed = { apply: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--apply' && !parsed.apply) parsed.apply = true;
    else if (args[i] === '--pr' && parsed.number === undefined && /^[1-9][0-9]*$/.test(args[i + 1]))
      parsed.number = Number(args[++i]);
    else if (
      args[i] === '--head' &&
      parsed.head === undefined &&
      /^[a-f0-9]{40}$/.test(args[i + 1])
    )
      parsed.head = args[++i];
    else throw new PolicyError('INVALID_ARGUMENTS');
  }
  requirePolicy(
    Number.isSafeInteger(parsed.number) && parsed.number > 0 && /^[a-f0-9]{40}$/.test(parsed.head),
    'INVALID_ARGUMENTS',
  );
  return parsed;
}

export async function runMergeCli(args, { api = createGhClient(), readFile = readFileSync } = {}) {
  const parsed = parseMergeArguments(args);
  const policy = validatePolicy(
    JSON.parse(readFile(new URL('./contributor-policy.json', import.meta.url), 'utf8')),
  );
  const pr = await api(`repos/${policy.repository}/pulls/${parsed.number}`);
  return mergeReviewedPr(api, policy, { ...parsed, base: pr.base?.sha });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    console.log(JSON.stringify(await runMergeCli(process.argv.slice(2))));
  } catch (error) {
    console.error(
      JSON.stringify({
        state: 'failure',
        code: error instanceof PolicyError ? error.code : 'POLICY_ERROR',
        ...(error instanceof PolicyError && error.mergeSha
          ? { mergedCommitRequiresInspection: error.mergeSha }
          : {}),
      }),
    );
    process.exitCode = 1;
  }
}
