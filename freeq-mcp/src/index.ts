#!/usr/bin/env node
/**
 * `@freeq/mcp` — MCP server for freeq, over stdio.
 *
 * Install into any MCP client by pointing it at the built entry point:
 *
 *   { "mcpServers": { "freeq": { "command": "node", "args": ["…/freeq-mcp/dist/index.js"] } } }
 *
 * (`npx -y @freeq/mcp` once the package is published; it is not yet.)
 *
 * Nothing is written to stdout except JSON-RPC frames: stdout *is* the
 * transport, and a stray `console.log` corrupts the stream. Diagnostics go to
 * stderr, which MCP hosts surface in their logs.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createFreeqMcpServer } from "./server.js";

export { createFreeqMcpServer, INSTRUCTIONS, VERSION } from "./server.js";
export { loadConfig, deriveWsUrl, DEFAULT_SERVER } from "./config.js";
export type { FreeqMcpConfig } from "./config.js";
export { FreeqRest } from "./rest.js";
export { FreeqSession } from "./session.js";

async function main(): Promise<void> {
  const cfg = loadConfig();
  const mcp = createFreeqMcpServer({ cfg });

  process.stderr.write(
    `freeq-mcp: server=${cfg.baseUrl} identity=${cfg.ownerDid ? "did:key agent" : "guest"} ` +
      `writes=${cfg.allowWrites ? "on" : "off"}\n`,
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
  main().catch((err) => {
    process.stderr.write(`freeq-mcp: fatal: ${(err as Error).stack ?? err}\n`);
    process.exit(1);
  });
}
