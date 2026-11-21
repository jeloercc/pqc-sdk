import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SHA = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const EMAIL = /^[^\s<>@]+@[^\s<>@]+$/;

export class PolicyError extends Error {
  constructor(code) {
    const safe = /^[A-Z_]{1,50}$/.test(code) ? code : 'POLICY_ERROR';
    super(safe);
    this.code = safe;
  }
}

export function requirePolicy(condition, code) {
  if (!condition) throw new PolicyError(code);
}

const identifier = (value) => Number.isSafeInteger(value) && value > 0;
const strings = (values) =>
  Array.isArray(values) &&
  values.length > 0 &&
  new Set(values).size === values.length &&
  values.every(
    (v) =>
      typeof v === 'string' &&
      v.length > 0 &&
      v.length <= 150 &&
      Array.from(v).every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127),
  );

export function validatePolicy(policy) {
  const keys = [
    'version',
    'repository',
    'baseBranch',
    'baseline',
    'owner',
    'context',
    'maxPrCommits',
    'statusCreatorId',
    'actionsAppId',
    'requiredChecks',
  ];
  requirePolicy(
    policy &&
      Object.keys(policy).length === keys.length &&
      keys.every((k) => Object.hasOwn(policy, k)),
    'INVALID_POLICY',
  );
  const owner = policy.owner;
  requirePolicy(
    policy.version === 1 &&
      REPOSITORY.test(policy.repository) &&
      policy.baseBranch === 'main' &&
      SHA.test(policy.baseline),
    'INVALID_POLICY',
  );
  requirePolicy(
    owner &&
      Object.keys(owner).length === 4 &&
      ['id', 'login', 'names', 'emails'].every((k) => Object.hasOwn(owner, k)) &&
      identifier(owner.id) &&
      typeof owner.login === 'string' &&
      /^[A-Za-z0-9-]+$/.test(owner.login) &&
      strings(owner.names) &&
      strings(owner.emails) &&
      owner.emails.every((v) => EMAIL.test(v)),
    'INVALID_POLICY',
  );
  requirePolicy(
    typeof policy.context === 'string' &&
      /^[a-z0-9/_-]{1,80}$/.test(policy.context) &&
      Number.isInteger(policy.maxPrCommits) &&
      policy.maxPrCommits >= 1 &&
      policy.maxPrCommits <= 250 &&
      identifier(policy.statusCreatorId) &&
      identifier(policy.actionsAppId) &&
      strings(policy.requiredChecks),
    'INVALID_POLICY',
  );
  return policy;
}

export function policyDigest(policy) {
  validatePolicy(policy);
  const canonical = (value) =>
    Array.isArray(value)
      ? value.map(canonical)
      : value && typeof value === 'object'
        ? Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((k) => [k, canonical(value[k])]),
          )
        : value;
  return createHash('sha256')
    .update(JSON.stringify(canonical(policy)))
    .digest('hex');
}

export function policyStatusDescription(base, digest) {
  requirePolicy(SHA.test(base) && /^[a-f0-9]{64}$/.test(digest), 'INVALID_POLICY');
  return `owner-policy ${base} ${digest}`;
}

export function assertAuthorship(record, policy) {
  requirePolicy(
    record &&
      policy.owner.names.includes(record.name) &&
      typeof record.email === 'string' &&
      policy.owner.emails.some((e) => e.toLowerCase() === record.email.toLowerCase()),
    'AUTHOR_NOT_ALLOWED',
  );
  requirePolicy(
    typeof record.message === 'string' && !record.message.includes('\0'),
    'INVALID_COMMIT',
  );
  requirePolicy(!/^\s*co-authored-by\s*:/im.test(record.message), 'COAUTHOR_NOT_ALLOWED');
}

export function assertAssociatedCommit(record, policy, expectedSha) {
  requirePolicy(
    record && SHA.test(record.sha) && (!expectedSha || record.sha === expectedSha),
    'HEAD_CHANGED',
  );
  requirePolicy(
    record.author?.id === policy.owner.id && record.author?.type !== 'Bot',
    'COMMIT_ACCOUNT_NOT_ALLOWED',
  );
  assertAuthorship({ ...record.commit?.author, message: record.commit?.message }, policy);
}

export function validateApiPath(path) {
  requirePolicy(
    typeof path === 'string' &&
      /^(?:repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_./?=&%-]+|user)$/.test(path) &&
      !path.includes('..') &&
      !path.includes('//') &&
      !/%(?:2e|2f|5c)/i.test(path),
    'INVALID_API_PATH',
  );
}

export function createGitHubClient({ token, fetchImpl = globalThis.fetch }) {
  requirePolicy(typeof token === 'string' && token.length > 0, 'MISSING_TOKEN');
  return async (path, { method = 'GET', body } = {}) => {
    validateApiPath(path);
    requirePolicy(
      method === 'GET' ||
        (method === 'POST' && /^repos\/[^/]+\/[^/]+\/statuses\/[a-f0-9]{40}$/.test(path)),
      'INVALID_API_PATH',
    );
    try {
      const response = await fetchImpl(`https://api.github.com/${path}`, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2026-03-10',
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      requirePolicy(response.ok, 'API_ERROR');
      return await response.json();
    } catch {
      throw new PolicyError('API_ERROR');
    }
  };
}

function assertPr(pr, policy, expected) {
  requirePolicy(
    pr && pr.number === expected.number && pr.state === 'open' && pr.draft === false,
    'PR_NOT_READY',
  );
  requirePolicy(pr.user?.id === policy.owner.id, 'PR_AUTHOR_NOT_ALLOWED');
  requirePolicy(
    pr.base?.repo?.full_name === policy.repository &&
      pr.head?.repo?.full_name === policy.repository,
    'WRONG_REPOSITORY',
  );
  requirePolicy(pr.base.ref === policy.baseBranch, 'WRONG_BASE');
  requirePolicy(SHA.test(expected.head) && pr.head.sha === expected.head, 'HEAD_CHANGED');
  requirePolicy(SHA.test(expected.base) && pr.base.sha === expected.base, 'BASE_CHANGED');
  requirePolicy(
    Number.isInteger(pr.commits) && pr.commits >= 1 && pr.commits <= policy.maxPrCommits,
    'INCOMPLETE_COMMITS',
  );
}

export async function inspectPullRequest(api, policy, expected) {
  validatePolicy(policy);
  requirePolicy(identifier(expected.number), 'INVALID_PR_NUMBER');
  const prefix = `repos/${policy.repository}`;
  const pr = await api(`${prefix}/pulls/${expected.number}`);
  assertPr(pr, policy, expected);
  requirePolicy(
    (await api(`${prefix}/git/ref/heads/${policy.baseBranch}`)).object?.sha === expected.base,
    'BASE_CHANGED',
  );
  const commits = [];
  for (let page = 1; page <= Math.ceil(pr.commits / 100); page++) {
    const batch = await api(`${prefix}/pulls/${expected.number}/commits?per_page=100&page=${page}`);
    requirePolicy(Array.isArray(batch) && batch.length <= 100, 'INCOMPLETE_COMMITS');
    commits.push(...batch);
  }
  requirePolicy(
    commits.length === pr.commits &&
      new Set(commits.map((c) => c.sha)).size === commits.length &&
      commits.some((c) => c.sha === expected.head),
    'INCOMPLETE_COMMITS',
  );
  for (const commit of commits) assertAssociatedCommit(commit, policy);
  const head = await api(`${prefix}/commits/${expected.head}`);
  assertAssociatedCommit(head, policy, expected.head);
  requirePolicy(SHA.test(head.commit.tree?.sha), 'INVALID_COMMIT');
  const current = await api(`${prefix}/pulls/${expected.number}`);
  assertPr(current, policy, expected);
  requirePolicy(
    current.commits === pr.commits &&
      (await api(`${prefix}/git/ref/heads/${policy.baseBranch}`)).object?.sha === expected.base,
    'BASE_CHANGED',
  );
  return { ...expected, tree: head.commit.tree.sha, commits, pr: current };
}

function git(cwd, args, input) {
  try {
    return execFileSync('git', args, {
      cwd,
      input,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0' },
    });
  } catch {
    throw new PolicyError('GIT_ERROR');
  }
}

export function inspectGitHistory(cwd, head, policy) {
  validatePolicy(policy);
  requirePolicy(SHA.test(head), 'CHECKOUT_MISMATCH');
  requirePolicy(
    git(cwd, ['rev-parse', '--is-shallow-repository']).toString().trim() === 'false',
    'SHALLOW_HISTORY',
  );
  requirePolicy(git(cwd, ['rev-parse', 'HEAD']).toString().trim() === head, 'CHECKOUT_MISMATCH');
  try {
    git(cwd, ['merge-base', '--is-ancestor', policy.baseline, head]);
  } catch {
    throw new PolicyError('BASELINE_NOT_ANCESTOR');
  }
  const ids = git(cwd, ['rev-list', '--reverse', '--topo-order', head])
    .toString()
    .trim()
    .split('\n');
  requirePolicy(ids.length > 0 && ids.every((id) => SHA.test(id)), 'INVALID_HISTORY');
  const objects = git(cwd, ['cat-file', '--batch'], ids.join('\n') + '\n');
  const records = [];
  let offset = 0;
  for (const sha of ids) {
    const end = objects.indexOf(10, offset);
    const header = objects
      .subarray(offset, end)
      .toString()
      .match(/^([a-f0-9]{40}) commit ([0-9]+)$/);
    requirePolicy(end >= offset && header?.[1] === sha, 'INVALID_HISTORY');
    const size = Number(header[2]),
      start = end + 1;
    requirePolicy(
      Number.isSafeInteger(size) &&
        size > 0 &&
        start + size < objects.length &&
        objects[start + size] === 10,
      'INVALID_HISTORY',
    );
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(
        objects.subarray(start, start + size),
      );
    } catch {
      throw new PolicyError('INVALID_HISTORY');
    }
    const split = text.indexOf('\n\n');
    requirePolicy(split > 0 && !text.includes('\0'), 'INVALID_HISTORY');
    const authors = text
      .slice(0, split)
      .split('\n')
      .filter((line) => line.startsWith('author '));
    const author =
      authors.length === 1 && authors[0].match(/^author (.+) <([^<>\r\n]+)> [0-9]+ [+-][0-9]{4}$/);
    requirePolicy(author, 'INVALID_HISTORY');
    const record = {
      sha,
      author: { name: author[1], email: author[2] },
      message: text.slice(split + 2),
    };
    assertAuthorship({ ...record.author, message: record.message }, policy);
    records.push(record);
    offset = start + size + 1;
  }
  requirePolicy(offset === objects.length, 'INVALID_HISTORY');
  return records;
}

export async function verifyMain(api, policy, { cwd, head }) {
  validatePolicy(policy);
  requirePolicy(SHA.test(head), 'CHECKOUT_MISMATCH');
  const prefix = `repos/${policy.repository}`;
  requirePolicy(
    (await api(`${prefix}/git/ref/heads/${policy.baseBranch}`)).object?.sha === head,
    'BASE_CHANGED',
  );
  const commit = await api(`${prefix}/commits/${head}`);
  assertAssociatedCommit(commit, policy, head);
  const records = inspectGitHistory(cwd, head, policy);
  requirePolicy(
    commit.commit.tree?.sha ===
      git(cwd, ['rev-parse', `${head}^{tree}`])
        .toString()
        .trim(),
    'TREE_MISMATCH',
  );
  requirePolicy(
    (await api(`${prefix}/git/ref/heads/${policy.baseBranch}`)).object?.sha === head,
    'BASE_CHANGED',
  );
  return { state: 'success', head, commits: records.length };
}

export async function runPullRequestGuard(api, policy, event, { sourceSha, runId }) {
  validatePolicy(policy);
  const pr = event?.pull_request;
  requirePolicy(
    event?.repository?.full_name === policy.repository &&
      pr?.base?.repo?.full_name === policy.repository &&
      pr.base.ref === policy.baseBranch &&
      pr.base.sha === sourceSha &&
      SHA.test(sourceSha) &&
      SHA.test(pr.head?.sha) &&
      identifier(event.number) &&
      /^[1-9][0-9]*$/.test(runId),
    'UNTRUSTED_CONTEXT',
  );
  const expected = { number: event.number, head: pr.head.sha, base: sourceSha };
  const path = `repos/${policy.repository}/statuses/${expected.head}`;
  const status = (state, description) =>
    api(path, {
      method: 'POST',
      body: {
        state,
        context: policy.context,
        description,
        target_url: `https://github.com/${policy.repository}/actions/runs/${runId}`,
      },
    });
  try {
    await status('pending', 'Checking owner attribution');
    const snapshot = await inspectPullRequest(api, policy, expected);
    await status('success', policyStatusDescription(snapshot.base, policyDigest(policy)));
    return {
      state: 'success',
      head: snapshot.head,
      base: snapshot.base,
      commits: snapshot.commits.length,
    };
  } catch (error) {
    const safe = error instanceof PolicyError ? error : new PolicyError('API_ERROR');
    try {
      await status('failure', `Owner attribution rejected: ${safe.code}`);
    } catch {
      /* An unavailable API cannot invalidate a previous status. */
    }
    throw safe;
  }
}

export async function runCheckerCli(
  args,
  { env = process.env, cwd = process.cwd(), readFile = readFileSync, api } = {},
) {
  requirePolicy(
    args.length === 1 && ['--pull-request', '--main'].includes(args[0]),
    'INVALID_ARGUMENTS',
  );
  const policy = validatePolicy(
    JSON.parse(readFile(new URL('./contributor-policy.json', import.meta.url), 'utf8')),
  );
  requirePolicy(env.GITHUB_REPOSITORY === policy.repository, 'WRONG_REPOSITORY');
  if (args[0] === '--pull-request') {
    requirePolicy(
      env.GITHUB_EVENT_NAME === 'pull_request_target' && env.GITHUB_EVENT_PATH,
      'UNTRUSTED_CONTEXT',
    );
    const event = JSON.parse(readFile(env.GITHUB_EVENT_PATH, 'utf8'));
    return runPullRequestGuard(
      api ?? createGitHubClient({ token: env.GITHUB_TOKEN }),
      policy,
      event,
      { sourceSha: env.GITHUB_SHA, runId: env.GITHUB_RUN_ID },
    );
  }
  requirePolicy(
    env.GITHUB_EVENT_NAME === 'push' && env.GITHUB_REF === `refs/heads/${policy.baseBranch}`,
    'UNTRUSTED_CONTEXT',
  );
  return verifyMain(api ?? createGitHubClient({ token: env.GITHUB_TOKEN }), policy, {
    cwd,
    head: env.GITHUB_SHA,
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    console.log(JSON.stringify(await runCheckerCli(process.argv.slice(2))));
  } catch (error) {
    console.error(
      JSON.stringify({
        state: 'failure',
        code: error instanceof PolicyError ? error.code : 'POLICY_ERROR',
      }),
    );
    process.exitCode = 1;
  }
}
