import { PqcError } from '@pqc-sdk/core';

import { error } from './ui.js';

/**
 * An expected, user-correctable failure: a missing file, a refusal to
 * overwrite, an invalid flag value. Commands throw it (usually via
 * {@link friendlyRun}'s contract) so the top level prints one clean line
 * instead of a stack trace.
 */
export class UsageError extends Error {}

/**
 * Wraps a command's `run` so expected failures ({@link UsageError} from the
 * CLI itself, {@link PqcError} from the SDK) print a single clean message on
 * stderr and exit with code 1. Anything else — a real bug — is rethrown for
 * citty to report with its stack trace.
 *
 * @example
 * ```ts
 * import { defineCommand } from 'citty';
 * import { friendlyRun, UsageError } from '../errors.js';
 *
 * export const example = defineCommand({
 *   meta: { name: 'example', description: 'Demonstrates friendlyRun' },
 *   run: friendlyRun(async () => {
 *     throw new UsageError('Printed as one line, exit code 1.');
 *   }),
 * });
 * ```
 */
export function friendlyRun<Context>(
  run: (context: Context) => Promise<void>,
): (context: Context) => Promise<void> {
  return async (context) => {
    try {
      await run(context);
    } catch (cause) {
      if (cause instanceof UsageError || cause instanceof PqcError) {
        error(cause.message);
        process.exit(1);
      }
      throw cause;
    }
  };
}
