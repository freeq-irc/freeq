/**
 * stdout is the MCP transport: Claude Code reads JSON-RPC from it, and any
 * other line written there corrupts the stream. Everything that logs with
 * console.log, info or debug (the SDK logs dropped lines with console.debug,
 * `freeq-sdk-js/src/log.ts`) is sent to stderr instead. Called first, before
 * anything that might log.
 */
import { format } from "node:util";

export function routeConsoleToStderr(): void {
  const toStderr = (...args: unknown[]): void => {
    process.stderr.write(`${format(...args)}\n`);
  };
  console.log = toStderr;
  console.info = toStderr;
  console.debug = toStderr;
}
