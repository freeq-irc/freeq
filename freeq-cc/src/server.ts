#!/usr/bin/env node
/**
 * freeq-cc's entry: the MCP stdio server Claude Code starts, as the `freeq`
 * plugin's server `freeq` (`.claude-plugin/plugin.json`). Start Claude Code
 * with `--plugin-dir <freeq-cc> --dangerously-load-development-channels
 * plugin:freeq@inline` (README).
 *
 * Env: FREEQ_CC_DIR overrides the state directory (`~/.freeq/cc`);
 * CLAUDE_PROJECT_DIR, which Claude Code sets for stdio servers, is the
 * session's project.
 */
import { routeConsoleToStderr } from "./stdout.js";

// Before anything that might log: stdout is the MCP transport.
routeConsoleToStderr();

const { homedir } = await import("node:os");
const { join } = await import("node:path");
const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
const { setLogger } = await import("@freeq/sdk");
const { createChannel } = await import("./channel.js");

const log = (line: string): void => void process.stderr.write(`${line}\n`);

setLogger({
  error: (m, ...a) => log(`freeq-cc sdk: ${[m, ...a].join(" ")}`),
  warn: (m, ...a) => log(`freeq-cc sdk: ${[m, ...a].join(" ")}`),
  debug: (m, ...a) => {
    if (process.env.FREEQ_CC_DEBUG) log(`freeq-cc sdk: ${[m, ...a].join(" ")}`);
  },
});

const channel = await createChannel({
  agentDir: process.env.FREEQ_CC_DIR || join(homedir(), ".freeq", "cc"),
  cwd: () => process.env.CLAUDE_PROJECT_DIR || process.cwd(),
  log,
});

let stopping = false;
const stop = async (why: string): Promise<void> => {
  if (stopping) return;
  stopping = true;
  log(`freeq-cc: stopping (${why})`);
  try {
    await channel.stop();
  } finally {
    process.exit(0);
  }
};
process.once("SIGINT", () => void stop("SIGINT"));
process.once("SIGTERM", () => void stop("SIGTERM"));
// Claude Code closing the pipe is the session ending.
process.stdin.once("end", () => void stop("stdin closed"));
process.stdin.once("close", () => void stop("stdin closed"));

await channel.server.connect(new StdioServerTransport());
log("freeq-cc: ready");
