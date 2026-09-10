/**
 * Where the SDK's diagnostics go.
 *
 * They used to go to `console`, unconditionally. That is fine in a browser
 * and fine in a script, and it is destructive inside a full-screen terminal
 * UI: anything written straight to stdout lands in the middle of whatever the
 * renderer had drawn there, and the frame is corrupted until something forces
 * a full repaint. A flapping connection turned that into a flood — one
 * `[transport] Dropped message (ws not open): HEARTBEAT` per beat, painted
 * over the host's own layout.
 *
 * So the SDK writes diagnostics here instead, and a host that owns the screen
 * installs its own sink:
 *
 * ```ts
 * setLogger({ warn: (m, ...a) => ui.debug(m, ...a), error: …, debug: … });
 * setLogger(null); // silence entirely
 * ```
 *
 * The default is `console`, so nothing changes for a script, a browser, or a
 * test that was reading stderr. Only a host that asks gets something else.
 */

export interface Logger {
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
  debug(message: string, ...args: unknown[]): void;
}

const CONSOLE_LOGGER: Logger = {
  warn: (m, ...a) => console.warn(m, ...a),
  error: (m, ...a) => console.error(m, ...a),
  debug: (m, ...a) => console.debug(m, ...a),
};

const SILENT: Logger = { warn: () => {}, error: () => {}, debug: () => {} };

let active: Logger = CONSOLE_LOGGER;

/**
 * Install a diagnostics sink. `null` silences the SDK; no argument restores
 * the console default.
 *
 * A partial logger is filled in from the console default, so a host that only
 * cares about errors does not have to stub the rest.
 */
export function setLogger(logger?: Partial<Logger> | null): void {
  if (logger === null) {
    active = SILENT;
    return;
  }
  if (!logger) {
    active = CONSOLE_LOGGER;
    return;
  }
  active = {
    warn: logger.warn?.bind(logger) ?? CONSOLE_LOGGER.warn,
    error: logger.error?.bind(logger) ?? CONSOLE_LOGGER.error,
    debug: logger.debug?.bind(logger) ?? CONSOLE_LOGGER.debug,
  };
}

/** The sink in force. Call through this, never through `console`. */
export const log: Logger = {
  warn: (m, ...a) => active.warn(m, ...a),
  error: (m, ...a) => active.error(m, ...a),
  debug: (m, ...a) => active.debug(m, ...a),
};
