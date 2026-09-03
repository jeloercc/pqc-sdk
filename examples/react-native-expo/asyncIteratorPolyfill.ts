/**
 * Hermes implements no part of ES2018 async iteration.
 *
 * Verified against React Native 0.81.5's own bundled compiler
 * (`sdks/hermesc`, hermes-2025-07-07-RNv0.81.0), which still rejects
 * `async function*` and `for await...of` outright — this is current Hermes,
 * not a stale standalone build. Metro's Babel preset therefore downlevels
 * both, and the SDK's streaming API works on device as a result.
 *
 * One gap that downlevelling does not close: Babel's transpiled async
 * generators expose their iterator method under the **string** key
 * `"@@asyncIterator"`, because `Symbol.asyncIterator` does not exist to key
 * it under. Babel's own `for await` helper knows to look there, so code
 * Babel compiled end-to-end is fine. But any explicit
 * `object[Symbol.asyncIterator]()` lookup — which `@pqc-sdk/core`'s
 * `decryptStream` and the Web Streams adapters do — evaluates
 * `object[undefined]` and throws `TypeError: undefined is not a function`.
 *
 * Aliasing `Symbol.asyncIterator` to that same string makes those explicit
 * lookups resolve to Babel's method. It must run before any module that
 * uses async iteration is evaluated, which is why it is the first import in
 * `App.tsx` — the same ordering requirement `react-native-get-random-values`
 * has. On a runtime that does implement async iteration (Node, Deno,
 * Workers, and any future Hermes that ships it) this is a no-op.
 */
if (typeof Symbol.asyncIterator === 'undefined') {
  // Deliberately a string, not a fresh Symbol: it has to equal the key
  // Babel actually used. A `Symbol('Symbol.asyncIterator')` here type-checks
  // and looks more correct, but silently fails to match — that exact
  // mistake is what the comment above exists to prevent.
  (Symbol as { asyncIterator?: unknown }).asyncIterator = '@@asyncIterator';
}

export const ASYNC_ITERATOR_IS_POLYFILLED = typeof Symbol.asyncIterator === 'string';
