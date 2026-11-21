export function createGhClient() {
  return async () => ({});
}
export async function assessMerge() {
  return { state: 'ready' };
}
export async function mergeReviewedPr() {
  return { state: 'dry-run' };
}
