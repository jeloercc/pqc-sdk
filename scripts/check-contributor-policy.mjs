export class PolicyError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
export function validatePolicy(policy) {
  return policy;
}
export function policyDigest() {
  return 'pending';
}
export function policyStatusDescription(base, digest) {
  return `owner-policy ${base} ${digest}`;
}
export function assertAuthorship() {}
export function createGitHubClient() {
  return async () => ({});
}
export async function inspectPullRequest(_api, _policy, expected) {
  return { ...expected, commits: [] };
}
export function inspectGitHistory() {
  return [];
}
export async function verifyMain() {
  return { state: 'success' };
}
export async function runPullRequestGuard() {
  return { state: 'success' };
}
