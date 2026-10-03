/**
 * Copy fidelity: how accurately the model reproduces a ciphertext it was
 * given (by `pqc_encrypt` or in the prompt) when it calls `pqc_decrypt`.
 */

/** Strings longer than this skip the O(n·m) edit distance; only the length difference is kept. */
export const MAX_EDIT_DISTANCE_LENGTH = 20_000;

/** Levenshtein distance (insert, delete, substitute; all cost 1). */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = new Uint32Array(b.length + 1);
  let curr = new Uint32Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= b.length; j++) {
      const cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}

export interface CopyRecord {
  /** Whether any reference ciphertext was available to compare against. */
  readonly hasReference: boolean;
  /** Byte-for-byte identical to a reference. */
  readonly exact: boolean;
  /** Identical after dropping whitespace and a `0x` prefix and lowercasing. */
  readonly normalizedExact: boolean;
  /** Edit distance to the nearest reference; `null` when too long to compute or no reference. */
  readonly distance: number | null;
  /** `sentLength - referenceLength` for the nearest reference (0 without a reference). */
  readonly lengthDiff: number;
  readonly sentLength: number;
  readonly referenceLength: number;
}

function normalizeHex(value: string): string {
  return value.replace(/\s+/g, '').replace(/^0x/i, '').toLowerCase();
}

/** Compares the ciphertext the model sent against every reference and keeps the nearest. */
export function compareCopy(sent: string, references: readonly string[]): CopyRecord {
  if (references.length === 0) {
    return {
      hasReference: false,
      exact: false,
      normalizedExact: false,
      distance: null,
      lengthDiff: 0,
      sentLength: sent.length,
      referenceLength: 0,
    };
  }
  const exactRef = references.find((ref) => ref === sent);
  const normalizedSent = normalizeHex(sent);
  const normalizedRef = references.find((ref) => normalizeHex(ref) === normalizedSent);
  if (exactRef !== undefined || normalizedRef !== undefined) {
    const ref = exactRef ?? normalizedRef ?? '';
    return {
      hasReference: true,
      exact: exactRef !== undefined,
      normalizedExact: true,
      distance: exactRef !== undefined ? 0 : editDistance(sent, ref),
      lengthDiff: sent.length - ref.length,
      sentLength: sent.length,
      referenceLength: ref.length,
    };
  }

  // Nearest reference by length first (cheap), then by distance when computable.
  let best: { ref: string; distance: number | null } | undefined;
  for (const ref of references) {
    const computable =
      sent.length <= MAX_EDIT_DISTANCE_LENGTH && ref.length <= MAX_EDIT_DISTANCE_LENGTH;
    const distance = computable ? editDistance(sent, ref) : null;
    const better =
      best === undefined ||
      (distance !== null && (best.distance === null || distance < best.distance)) ||
      (distance === null &&
        best.distance === null &&
        Math.abs(sent.length - ref.length) < Math.abs(sent.length - best.ref.length));
    if (better) best = { ref, distance };
  }
  const nearest = best ?? { ref: '', distance: null };
  return {
    hasReference: true,
    exact: false,
    normalizedExact: false,
    distance: nearest.distance,
    lengthDiff: sent.length - nearest.ref.length,
    sentLength: sent.length,
    referenceLength: nearest.ref.length,
  };
}
