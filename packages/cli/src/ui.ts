import pc from 'picocolors';

/**
 * Helpers de salida. picocolors desactiva los colores automáticamente cuando
 * no hay TTY (y NO_COLOR/FORCE_COLOR se respetan), así el output queda legible
 * en pipes y logs de CI sin códigos ANSI.
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
  console.log(`    ${pc.dim('migrar a:')} ${pc.cyan(migrateTo)}`);
};

export const heading = (message: string): void => {
  console.log(pc.bold(message));
};
