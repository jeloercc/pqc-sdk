import pc from 'picocolors';

/**
 * Output helpers. picocolors disables colors automatically when there is no
 * TTY (and NO_COLOR/FORCE_COLOR are honored), so output stays readable in
 * pipes and CI logs without ANSI codes.
 */
export const ok = (message: string): void => {
  console.log(`${pc.green('✓')} ${message}`);
};

export const warn = (message: string): void => {
  console.log(`${pc.yellow('⚠')} ${pc.yellow(message)}`);
};

export const item = (message: string): void => {
  console.log(`  ${message}`);
};

export const finding = (location: string, what: string, migrateTo: string): void => {
  console.log(`  ${pc.red('●')} ${pc.bold(location)} — ${what}`);
  console.log(`    ${pc.dim('migrate to:')} ${pc.cyan(migrateTo)}`);
};

export const heading = (message: string): void => {
  console.log(pc.bold(message));
};
