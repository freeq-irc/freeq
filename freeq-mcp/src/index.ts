#!/usr/bin/env node
/**
 * `@freeq/mcp` — MCP server for freeq, over stdio; also `freeq-mcp room …`.
 *
 * Install into any MCP client by pointing it at the built entry point:
 *
 *   { "mcpServers": { "freeq": { "command": "node", "args": ["…/freeq-mcp/dist/index.js"] } } }
 *
 * (`npx -y @freeq/mcp` once the package is published; it is not yet.)
 *
 * Nothing is written to stdout except JSON-RPC frames: stdout *is* the
 * transport, and a stray `console.log` corrupts the stream. Diagnostics go to
 * stderr, which MCP hosts surface in their logs. The one exception is the
 * `room` subcommand, which is a one-shot CLI and owns stdout for its output.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { setLogger } from "@freeq/sdk";
import { runRoomCli } from "./cli.js";
import { loadConfig } from "./config.js";
import { createFreeqMcpServer } from "./server.js";

export { createFreeqMcpServer, INSTRUCTIONS, VERSION } from "./server.js";
export { loadConfig, deriveWsUrl, DEFAULT_SERVER } from "./config.js";
export type { FreeqMcpConfig } from "./config.js";
export { FreeqRest } from "./rest.js";
export { FreeqSession } from "./session.js";
export { parseRoomArgs, runRoomCli, ROOM_USAGE } from "./cli.js";

async function main(): Promise<void> {
  const cfg = loadConfig();
  const mcp = createFreeqMcpServer({ cfg });

  const identity = cfg.guest ? "guest" : cfg.ownerDid ? "did:key agent" : "did:key agent (self-owned)";
  process.stderr.write(
    `freeq-mcp: server=${cfg.baseUrl} identity=${identity} writes=${cfg.allowWrites ? "on" : "off"}\n`,
  );

  const shutdown = async (signal: string) => {
    process.stderr.write(`freeq-mcp: ${signal}, shutting down\n`);
    try {
      await mcp.close();
    } finally {
      process.exit(0);
    }
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  await mcp.server.connect(new StdioServerTransport());
}

// Only run when executed directly, so importing this module (tests, embedding)
// doesn't hijack stdio.
const invokedDirectly =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith("index.js") || process.argv[1].endsWith("freeq-mcp"));

if (invokedDirectly) {
  // The SDK's default sink is `console`, whose `debug` goes to stdout in
  // Node. In MCP mode that would splice a transport diagnostic into the
  // JSON-RPC stream; in CLI mode into the JSON a caller parses. Route
  // warnings and errors to stderr, drop debug chatter.
  setLogger({
    warn: (m, ...a) => process.stderr.write(`freeq-sdk: ${[m, ...a].join(" ")}\n`),
    error: (m, ...a) => process.stderr.write(`freeq-sdk: ${[m, ...a].join(" ")}\n`),
    debug: () => undefined,
  });

  if (process.argv[2] === "room") {
    // One-shot CLI: decided before any MCP transport touches stdout.
    runRoomCli(process.argv.slice(3), {
      stdout: (t) => process.stdout.write(t),
      stderr: (t) => process.stderr.write(t),
    }).then(
      (code) => process.exit(code),
      (err) => {
        process.stderr.write(`freeq-mcp room: fatal: ${(err as Error).stack ?? err}\n`);
        process.exit(1);
      },
    );
  } else {
    main().catch((err) => {
      process.stderr.write(`freeq-mcp: fatal: ${(err as Error).stack ?? err}\n`);
      process.exit(1);
    });
  }
}
