import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  assertAuthorship,
  createGitHubClient,
  inspectGitHistory,
  inspectPullRequest,
  policyDigest,
  policyStatusDescription,
  runPullRequestGuard,
  runCheckerCli,
  validatePolicy,
  verifyMain,
} from '../check-contributor-policy.mjs';
import {
  assessMerge,
  createGhClient,
  mergeReviewedPr,
  parseMergeArguments,
  runMergeCli,
} from '../merge-reviewed-pr.mjs';

const HEAD = 'a'.repeat(40),
  BASE = 'b'.repeat(40),
  TREE = 'c'.repeat(40);
const policy = {
  version: 1,
  repository: 'example/project',
  baseBranch: 'main',
  baseline: BASE,
  owner: {
    id: 1001,
    login: 'maintainer',
    names: ['Maintainer'],
    emails: ['maintainer@example.test'],
  },
  context: 'policy/owner-attribution',
  maxPrCommits: 250,
  statusCreatorId: 1003,
  actionsAppId: 1004,
  requiredChecks: ['ci (node 20)', 'ci (node 24)', 'bench'],
};
const author = { name: 'Maintainer', email: 'maintainer@example.test' };
const commit = () => ({
  sha: HEAD,
  author: { id: 1001 },
  commit: { author: { ...author }, message: 'fix: reviewed update', tree: { sha: TREE } },
  parents: [{ sha: BASE }],
});
const error = (code) => (e) => e.code === code;

function fixture(overrides = {}) {
  const data = {
    pr: {
      number: 7,
      state: 'open',
      draft: false,
      user: { id: 1001 },
      commits: 1,
      head: { sha: HEAD, ref: 'owner-update', repo: { full_name: 'example/project' } },
      base: { sha: BASE, ref: 'main', repo: { full_name: 'example/project' } },
      mergeable: true,
      mergeable_state: 'clean',
      merged: false,
    },
    commits: [commit()],
    headCommit: commit(),
    main: BASE,
    checks: policy.requiredChecks.map((name) => ({
      name,
      status: 'completed',
      conclusion: 'success',
      app: { id: 1004 },
    })),
    statuses: [
      {
        sha: HEAD,
        context: policy.context,
        state: 'success',
        creator: { id: 1003 },
        description: policyStatusDescription(BASE, policyDigest(policy)),
        target_url: 'https://github.com/example/project/actions/runs/12',
      },
    ],
    run: {
      id: 12,
      path: '.github/workflows/attribution-policy.yml',
      event: 'pull_request_target',
      head_sha: HEAD,
      head_branch: 'owner-update',
      pull_requests: [
        {
          number: 7,
          head: {
            sha: HEAD,
            ref: 'owner-update',
            repo: { url: 'https://api.github.com/repos/example/project' },
          },
          base: {
            sha: BASE,
            ref: 'main',
            repo: { url: 'https://api.github.com/repos/example/project' },
          },
        },
      ],
      status: 'completed',
      conclusion: 'success',
    },
    ...overrides,
  };
  const calls = [];
  let prReads = 0;
  const api = async (path, options = {}) => {
    const method = options.method ?? 'GET';
    calls.push({ path, method, body: options.body });
    if (path.includes('/statuses/') && method === 'POST') return {};
    if (path === 'user') return { id: 1001, login: 'maintainer' };
    if (path.endsWith('/git/ref/heads/main')) return { object: { sha: data.main } };
    if (path.endsWith('/pulls/7/merge') && method === 'PUT')
      return { merged: true, sha: 'd'.repeat(40) };
    if (path.endsWith('/pulls/7')) {
      prReads++;
      return structuredClone(
        data.changeOnRead === prReads
          ? { ...data.pr, head: { ...data.pr.head, sha: 'e'.repeat(40) } }
          : data.pr,
      );
    }
    if (path.includes('/pulls/7/commits?'))
      return structuredClone(
        data.commits.slice(
          (Number(new URL(`https://api.github.com/${path}`).searchParams.get('page')) - 1) * 100,
          Number(new URL(`https://api.github.com/${path}`).searchParams.get('page')) * 100,
        ),
      );
    if (path.includes('/check-runs?'))
      return { total_count: data.checks.length, check_runs: structuredClone(data.checks) };
    if (path.includes(`/commits/${HEAD}/statuses?`)) return structuredClone(data.statuses);
    if (path.endsWith('/actions/runs/12')) return structuredClone(data.run);
    if (path.endsWith(`/commits/${HEAD}`)) return structuredClone(data.headCommit);
    if (path.endsWith(`/commits/${'d'.repeat(40)}`)) return { ...commit(), sha: 'd'.repeat(40) };
    throw new Error(`Unexpected fixture route: ${method} ${path}`);
  };
  return { data, calls, api };
}
const expected = { number: 7, head: HEAD, base: BASE };

test('policy rejects malformed identities, repositories, SHA and limits', () => {
  for (const changed of [
    { ...policy, repository: '../evil' },
    { ...policy, baseline: 'invalid' },
    { ...policy, maxPrCommits: 251 },
    { ...policy, context: undefined },
    { ...policy, owner: { ...policy.owner, id: 0 } },
    { ...policy, owner: { ...policy.owner, emails: [] } },
    { ...policy, owner: { ...policy.owner, login: undefined } },
    { ...policy, owner: { ...policy.owner, extra: 'unexpected' } },
  ])
    assert.throws(() => validatePolicy(changed), error('INVALID_POLICY'));
});
test('policy digest is stable across object ordering and changes with identity', () => {
  assert.match(policyDigest(policy), /^[a-f0-9]{64}$/);
  assert.equal(
    policyDigest(policy),
    policyDigest(Object.fromEntries(Object.entries(policy).reverse())),
  );
  assert.notEqual(
    policyDigest(policy),
    policyDigest({ ...policy, owner: { ...policy.owner, id: 2001 } }),
  );
});
test('owner author is allowed while bot, foreign names/emails and malformed data fail', () => {
  assert.doesNotThrow(() => assertAuthorship({ ...author, message: 'fix: update' }, policy));
  for (const data of [
    { ...author, name: 'automation[bot]' },
    { ...author, email: 'other@example.test' },
    { ...author, name: '' },
  ])
    assert.throws(
      () => assertAuthorship({ ...data, message: 'fix: update' }, policy),
      error('AUTHOR_NOT_ALLOWED'),
    );
  assert.throws(
    () => assertAuthorship({ ...author, message: 'bad\0message' }, policy),
    error('INVALID_COMMIT'),
  );
});
for (const trailer of [
  'Co-authored-by: Other <other@example.test>',
  '  CO-AUTHORED-BY : Other <other@example.test>',
  'Co-authored-by:\n Other <other@example.test>',
  'Co-authored-by: Maintainer <maintainer@example.test>',
])
  test(`rejects additional credit: ${JSON.stringify(trailer)}`, () => {
    assert.throws(
      () => assertAuthorship({ ...author, message: `fix: update\n\n${trailer}` }, policy),
      error('COAUTHOR_NOT_ALLOWED'),
    );
  });
test('reads complete owner PR and confirms head/base again without writes', async () => {
  const f = fixture();
  const result = await inspectPullRequest(f.api, policy, expected);
  assert.equal(result.head, HEAD);
  assert.equal(result.tree, TREE);
  assert.equal(result.commits.length, 1);
  assert.ok(f.calls.filter((c) => c.path.endsWith('/pulls/7')).length >= 2);
  assert.ok(f.calls.every((c) => c.method === 'GET'));
});
for (const [label, update, code] of [
  [
    'bot PR',
    (p) => {
      p.user.id = 2001;
    },
    'PR_AUTHOR_NOT_ALLOWED',
  ],
  [
    'draft',
    (p) => {
      p.draft = true;
    },
    'PR_NOT_READY',
  ],
  [
    'closed',
    (p) => {
      p.state = 'closed';
    },
    'PR_NOT_READY',
  ],
  [
    'foreign head',
    (p) => {
      p.head.repo.full_name = 'foreign/project';
    },
    'WRONG_REPOSITORY',
  ],
  [
    'foreign base',
    (p) => {
      p.base.repo.full_name = 'foreign/project';
    },
    'WRONG_REPOSITORY',
  ],
  [
    'different target',
    (p) => {
      p.base.ref = 'develop';
    },
    'WRONG_BASE',
  ],
  [
    'more than 250',
    (p) => {
      p.commits = 251;
    },
    'INCOMPLETE_COMMITS',
  ],
  [
    'wrong head',
    (p) => {
      p.head.sha = 'e'.repeat(40);
    },
    'HEAD_CHANGED',
  ],
  [
    'wrong base',
    (p) => {
      p.base.sha = 'e'.repeat(40);
    },
    'BASE_CHANGED',
  ],
])
  test(`PR rejects ${label}`, async () => {
    const f = fixture();
    update(f.data.pr);
    await assert.rejects(() => inspectPullRequest(f.api, policy, expected), error(code));
  });
test('rejects anonymous commits, unapproved coauthors and a dishonest head tree', async () => {
  for (const change of [
    (f) => {
      f.data.commits[0].author = null;
    },
    (f) => {
      f.data.commits[0].commit.message += '\nCo-authored-by: Other <other@example.test>';
    },
  ]) {
    const f = fixture();
    change(f);
    await assert.rejects(() => inspectPullRequest(f.api, policy, expected));
  }
  const f = fixture();
  f.data.headCommit.sha = 'e'.repeat(40);
  await assert.rejects(() => inspectPullRequest(f.api, policy, expected), error('HEAD_CHANGED'));
});
test('paginates 250 commits and rejects truncated or duplicate lists', async () => {
  const f = fixture();
  f.data.pr.commits = 250;
  f.data.commits = Array.from({ length: 249 }, (_, i) => ({
    ...commit(),
    sha: (i + 1).toString(16).padStart(40, '0'),
  })).concat(commit());
  assert.equal((await inspectPullRequest(f.api, policy, expected)).commits.length, 250);
  f.data.commits.pop();
  await assert.rejects(
    () => inspectPullRequest(f.api, policy, expected),
    error('INCOMPLETE_COMMITS'),
  );
  f.data.pr.commits = 2;
  f.data.commits = [commit(), commit()];
  await assert.rejects(
    () => inspectPullRequest(f.api, policy, expected),
    error('INCOMPLETE_COMMITS'),
  );
});
test('fails when the head changes during inspection or metadata/API is unavailable', async () => {
  const f = fixture({ changeOnRead: 2 });
  await assert.rejects(() => inspectPullRequest(f.api, policy, expected), error('HEAD_CHANGED'));
  await assert.rejects(() =>
    inspectPullRequest(
      async () => {
        throw new Error('synthetic transport error');
      },
      policy,
      expected,
    ),
  );
});
test('GitHub transport pins host, rejects redirects/HTTP failures and never exposes tokens', async () => {
  const calls = [];
  const api = createGitHubClient({
    token: 'synthetic-token',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response('{"ok":true}');
    },
  });
  assert.deepEqual(await api('repos/example/project/pulls/7'), { ok: true });
  assert.equal(calls[0].url, 'https://api.github.com/repos/example/project/pulls/7');
  assert.equal(calls[0].options.redirect, 'error');
  await assert.rejects(() => api('https://other.example.test/steal'), error('INVALID_API_PATH'));
  for (const status of [302, 401, 403, 500]) {
    const failed = createGitHubClient({
      token: 'synthetic-token',
      fetchImpl: async () => new Response('synthetic-token', { status }),
    });
    await assert.rejects(
      () => failed('repos/example/project/pulls/7'),
      (e) => e.code === 'API_ERROR' && !e.message.includes('synthetic-token'),
    );
  }
});

function gitFixture(t) {
  const cwd = mkdtempSync(join(tmpdir(), 'pqc-owner-policy-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Maintainer',
    GIT_AUTHOR_EMAIL: 'maintainer@example.test',
    GIT_COMMITTER_NAME: 'GitHub',
    GIT_COMMITTER_EMAIL: 'noreply@github.com',
  };
  const git = (...args) =>
    execFileSync('git', ['-c', 'core.hooksPath=/dev/null', ...args], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
      .toString()
      .trim();
  git('init', '--template=', '-b', 'main');
  git('commit', '--allow-empty', '-m', 'initial');
  const baseline = git('rev-parse', 'HEAD');
  git('commit', '--allow-empty', '-m', 'reviewed update');
  return { cwd, git, policy: { ...policy, baseline }, head: git('rev-parse', 'HEAD'), env };
}
test('Git validation accepts the owner with GitHub committer and checks all history', (t) => {
  const f = gitFixture(t);
  const result = inspectGitHistory(f.cwd, f.head, f.policy);
  assert.equal(result.length, 2);
  assert.ok(result.every((c) => c.author.email === author.email));
});
test('Git validation rejects wrong checkout, shallow history and missing baseline', (t) => {
  const f = gitFixture(t);
  assert.throws(() => inspectGitHistory(f.cwd, BASE, f.policy), error('CHECKOUT_MISMATCH'));
  assert.throws(
    () => inspectGitHistory(f.cwd, f.head, { ...f.policy, baseline: 'e'.repeat(40) }),
    error('BASELINE_NOT_ANCESTOR'),
  );
  writeFileSync(join(f.cwd, '.git/shallow'), f.head + '\n');
  assert.throws(() => inspectGitHistory(f.cwd, f.head, f.policy), error('SHALLOW_HISTORY'));
});
test('Git validation rejects a foreign author behind a merge second parent', (t) => {
  const f = gitFixture(t);
  f.git('switch', '-c', 'foreign', f.policy.baseline);
  execFileSync(
    'git',
    ['-c', 'core.hooksPath=/dev/null', 'commit', '--allow-empty', '-m', 'foreign update'],
    {
      cwd: f.cwd,
      env: { ...f.env, GIT_AUTHOR_NAME: 'Other', GIT_AUTHOR_EMAIL: 'other@example.test' },
      stdio: 'pipe',
    },
  );
  f.git('switch', 'main');
  f.git('merge', '--no-ff', 'foreign', '-m', 'merge update');
  assert.throws(
    () => inspectGitHistory(f.cwd, f.git('rev-parse', 'HEAD'), f.policy),
    error('AUTHOR_NOT_ALLOWED'),
  );
});
test('main verification checks actual account/tree and never makes API writes', async (t) => {
  const f = gitFixture(t);
  const calls = [];
  const api = async (path) => {
    calls.push(path);
    if (path.includes('/git/ref/')) return { object: { sha: f.head } };
    return {
      ...commit(),
      sha: f.head,
      commit: {
        author,
        message: 'reviewed update',
        tree: { sha: f.git('rev-parse', 'HEAD^{tree}') },
      },
    };
  };
  assert.equal((await verifyMain(api, f.policy, { cwd: f.cwd, head: f.head })).commits, 2);
  await assert.rejects(
    () =>
      verifyMain(
        async (path) =>
          path.includes('/git/ref/')
            ? { object: { sha: f.head } }
            : { ...commit(), sha: f.head, author: { id: 2001 } },
        f.policy,
        { cwd: f.cwd, head: f.head },
      ),
    error('COMMIT_ACCOUNT_NOT_ALLOWED'),
  );
  assert.ok(calls.length >= 2);
});

const event = () => ({
  action: 'opened',
  number: 7,
  repository: { full_name: policy.repository },
  pull_request: { ...fixture().data.pr },
});
test('PR guard publishes pending/success only on the head and stamps base/policy', async () => {
  const f = fixture();
  await runPullRequestGuard(f.api, policy, event(), { sourceSha: BASE, runId: '12' });
  const writes = f.calls.filter((c) => c.method === 'POST');
  assert.deepEqual(
    writes.map((c) => c.body.state),
    ['pending', 'success'],
  );
  assert.ok(writes.every((c) => c.path.endsWith(`/statuses/${HEAD}`)));
  assert.equal(writes[1].body.description, policyStatusDescription(BASE, policyDigest(policy)));
});
test('PR guard rejects untrusted context without writes and records rejected authors', async () => {
  const f = fixture();
  await assert.rejects(
    () => runPullRequestGuard(f.api, policy, event(), { sourceSha: HEAD, runId: '12' }),
    error('UNTRUSTED_CONTEXT'),
  );
  assert.equal(f.calls.length, 0);
  f.data.pr.user.id = 2001;
  await assert.rejects(
    () => runPullRequestGuard(f.api, policy, event(), { sourceSha: BASE, runId: '12' }),
    error('PR_AUTHOR_NOT_ALLOWED'),
  );
  assert.deepEqual(
    f.calls.filter((c) => c.method === 'POST').map((c) => c.body.state),
    ['pending', 'failure'],
  );
});
test('GitHub status API errors never produce a success fallback', async () => {
  let writes = 0;
  await assert.rejects(() =>
    runPullRequestGuard(
      async () => {
        writes++;
        throw new Error('synthetic outage');
      },
      policy,
      event(),
      { sourceSha: BASE, runId: '12' },
    ),
  );
  assert.ok(writes > 0);
});
test('merge assessment requires real status creator, base stamp and trusted workflow', async () => {
  assert.equal((await assessMerge(fixture().api, policy, expected)).head, HEAD);
  for (const change of [
    (f) => {
      f.data.statuses = [];
    },
    (f) => {
      f.data.statuses[0].creator.id = 2001;
    },
    (f) => {
      f.data.statuses[0].description = 'outdated';
    },
    (f) => {
      f.data.run.event = 'pull_request';
    },
    (f) => {
      f.data.run.head_sha = BASE;
    },
    (f) => {
      f.data.checks[0].conclusion = 'failure';
    },
    (f) => {
      f.data.pr.mergeable_state = 'behind';
    },
  ]) {
    const f = fixture();
    change(f);
    await assert.rejects(() => assessMerge(f.api, policy, expected));
  }
});
test('merge helper defaults to dry-run, performs one exact-head squash only on apply', async () => {
  const f = fixture();
  const result = await mergeReviewedPr(f.api, policy, expected);
  assert.equal(result.state, 'dry-run');
  assert.ok(f.calls.every((c) => c.method === 'GET'));
  const applied = await mergeReviewedPr(f.api, policy, { ...expected, apply: true });
  assert.equal(applied.author, 'maintainer');
  const writes = f.calls.filter((c) => c.method !== 'GET');
  assert.equal(writes.length, 1);
  assert.equal(writes[0].body.sha, HEAD);
  assert.equal(writes[0].body.merge_method, 'squash');
  assert.ok(!writes[0].body.commit_message.toLowerCase().includes('co-authored-by:'));
});
test('merge result with unapproved author, tree or parent is rejected without repair writes', async () => {
  for (const [change, code] of [
    [
      (c) => {
        c.author.id = 2001;
      },
      'COMMIT_ACCOUNT_NOT_ALLOWED',
    ],
    [
      (c) => {
        c.commit.tree.sha = HEAD;
      },
      'TREE_MISMATCH',
    ],
    [
      (c) => {
        c.parents[0].sha = HEAD;
      },
      'BASE_CHANGED',
    ],
  ]) {
    const f = fixture();
    const merged = { ...commit(), sha: 'd'.repeat(40) };
    change(merged);
    const api = async (path, options) =>
      path.endsWith(`/commits/${'d'.repeat(40)}`) ? merged : f.api(path, options);
    await assert.rejects(
      () => mergeReviewedPr(api, policy, { ...expected, apply: true }),
      (e) => e.code === code && e.mergeSha === 'd'.repeat(40),
    );
    assert.equal(f.calls.filter((c) => c.method !== 'GET').length, 1);
  }
});
test('gh adapter pins hostname and passes JSON on stdin rather than a shell', async () => {
  const calls = [];
  const api = createGhClient({
    exec: (command, args, options) => {
      calls.push({ command, args, options });
      return '{}';
    },
  });
  await api('repos/example/project/pulls/7/merge', {
    method: 'PUT',
    body: { commit_message: 'literal $(text) `text`' },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'gh');
  assert.deepEqual(calls[0].args, [
    'api',
    '--hostname',
    'github.com',
    '--method',
    'PUT',
    'repos/example/project/pulls/7/merge',
    '--input',
    '-',
  ]);
  assert.equal(JSON.parse(calls[0].options.input).commit_message, 'literal $(text) `text`');
  assert.equal(calls[0].options.shell, undefined);
});

test('CLI requires a reviewed SHA and unique explicit arguments, with dry-run as default', () => {
  assert.deepEqual(parseMergeArguments(['--pr', '7', '--head', HEAD]), {
    number: 7,
    head: HEAD,
    apply: false,
  });
  assert.equal(parseMergeArguments(['--head', HEAD, '--apply', '--pr', '7']).apply, true);
  for (const args of [
    [],
    ['--pr', '7'],
    ['--pr', '0', '--head', HEAD],
    ['--pr', '7', '--head', 'main'],
    ['--pr', '7', '--head', HEAD, '--apply', '--apply'],
    ['--pr', '7', '--head', HEAD, '--pr', '8'],
    ['--pr', '7', '--head', HEAD, '--force'],
  ]) {
    assert.throws(() => parseMergeArguments(args), error('INVALID_ARGUMENTS'));
  }
});

test('merge CLI loads fixed policy and stays read-only unless apply is explicit', async () => {
  const f = fixture();
  const result = await runMergeCli(['--pr', '7', '--head', HEAD], {
    api: f.api,
    readFile: (path) => {
      assert.ok(String(path).endsWith('/contributor-policy.json'));
      return JSON.stringify(policy);
    },
  });
  assert.equal(result.state, 'dry-run');
  assert.ok(f.calls.every((c) => c.method === 'GET'));
});

test('checker CLI rejects unrelated events before any API write and dispatches trusted PR metadata', async () => {
  const f = fixture();
  const event = {
    repository: { full_name: policy.repository },
    number: 7,
    pull_request: f.data.pr,
  };
  const readFile = (path) =>
    String(path).endsWith('contributor-policy.json')
      ? JSON.stringify(policy)
      : JSON.stringify(event);
  const env = {
    GITHUB_REPOSITORY: policy.repository,
    GITHUB_EVENT_NAME: 'pull_request_target',
    GITHUB_EVENT_PATH: '/event.json',
    GITHUB_SHA: BASE,
    GITHUB_RUN_ID: '12',
  };
  for (const options of [
    { args: [], env },
    { args: ['--pull-request'], env: { ...env, GITHUB_REPOSITORY: 'other/project' } },
    { args: ['--pull-request'], env: { ...env, GITHUB_EVENT_NAME: 'pull_request' } },
    { args: ['--main'], env },
  ])
    await assert.rejects(() =>
      runCheckerCli(options.args, { env: options.env, readFile, api: f.api }),
    );
  assert.equal(f.calls.length, 0);
  const result = await runCheckerCli(['--pull-request'], { env, readFile, api: f.api });
  assert.equal(result.state, 'success');
});

test('checker CLI validates main through the same full-history gate', async (t) => {
  const f = gitFixture(t);
  const head = f.head;
  const p = { ...policy, baseline: head };
  const c = {
    ...commit(),
    sha: head,
    commit: { ...commit().commit, tree: { sha: f.git('rev-parse', 'HEAD^{tree}') } },
  };
  const api = async (path) => (path.includes('/git/ref/') ? { object: { sha: head } } : c);
  const result = await runCheckerCli(['--main'], {
    cwd: f.cwd,
    env: {
      GITHUB_REPOSITORY: p.repository,
      GITHUB_EVENT_NAME: 'push',
      GITHUB_REF: 'refs/heads/main',
      GITHUB_SHA: head,
    },
    readFile: () => JSON.stringify(p),
    api,
  });
  assert.equal(result.state, 'success');
});

test('transports reject forbidden mutations, invalid paths, and sanitize subprocess errors', async () => {
  const fetchApi = createGitHubClient({
    token: 'synthetic',
    fetchImpl: async () => {
      throw new Error('synthetic secret');
    },
  });
  assert.throws(() => createGitHubClient({ token: '' }), error('MISSING_TOKEN'));
  await assert.rejects(
    () => fetchApi('repos/example/project/pulls/7', { method: 'DELETE' }),
    error('INVALID_API_PATH'),
  );
  await assert.rejects(() => fetchApi('repos/example/project/../evil'), error('INVALID_API_PATH'));
  await assert.rejects(
    () => fetchApi('user'),
    (e) => e.code === 'API_ERROR' && !e.message.includes('secret'),
  );
  const ghApi = createGhClient({
    exec: () => {
      throw new Error('synthetic secret');
    },
  });
  await assert.rejects(() => ghApi('user'), error('API_ERROR'));
  await assert.rejects(() => ghApi('user', { method: 'POST' }), error('INVALID_API_PATH'));
});

test('merge assessment rejects incomplete checks, stale statuses, and an unapproved merger', async () => {
  for (const setup of [
    (f) => {
      f.data.checks = [];
    },
    (f) => {
      f.data.checks[0].app.id = 2001;
    },
    (f) => {
      f.data.statuses[0].sha = BASE;
    },
    (f) => {
      f.data.statuses[0].target_url = 'https://example.test/actions/runs/12';
    },
    (f) => {
      f.data.statuses[0].state = 'pending';
    },
  ]) {
    const f = fixture();
    setup(f);
    await assert.rejects(() => assessMerge(f.api, policy, expected));
    assert.ok(f.calls.every((c) => c.method === 'GET'));
  }
  const f = fixture();
  await assert.rejects(
    () =>
      assessMerge(async (path) => (path === 'user' ? { id: 2001 } : f.api(path)), policy, expected),
    error('MERGER_NOT_ALLOWED'),
  );
  await assert.rejects(
    () =>
      assessMerge(
        async (path) =>
          path.includes('/check-runs?') ? { total_count: 101, check_runs: [] } : f.api(path),
        policy,
        expected,
      ),
    error('CHECKS_INCOMPLETE'),
  );
});
