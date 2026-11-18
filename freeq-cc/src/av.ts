#!/usr/bin/env node
/**
 * The plugin's `av` MCP server: the freeq voice bridge (`freeq-claude-mcp`,
 * Rust, `freeq-agent-kit/examples/claude-mcp`), started from wherever it was
 * built. It joins a call, transcribes, speaks and projects a tile; the
 * plugin's `call` skill drives it.
 *
 * Looked for, in order: `$FREEQ_AV_BIN`; `$CLAUDE_PLUGIN_DATA/bin/`, where
 * `scripts/install-av.sh` puts it; `~/.freeq/cc/bin/`; the repository's own
 * `target/release/` when the plugin runs from a clone. When none is there, a
 * stand-in server answers with one tool, `av_setup`, that says how to build
 * it, so the session shows a working server and a way forward instead of a
 * failed one.
 */
import { spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = "freeq-claude-mcp";
const here = dirname(fileURLToPath(import.meta.url));

export function avCandidates(env: NodeJS.ProcessEnv = process.env): string[] {
  const out: string[] = [];
  if (env.FREEQ_AV_BIN) out.push(env.FREEQ_AV_BIN);
  if (env.CLAUDE_PLUGIN_DATA) out.push(join(env.CLAUDE_PLUGIN_DATA, "bin", BIN));
  out.push(join(homedir(), ".freeq", "cc", "bin", BIN));
  // dist/ → freeq-cc/ → the repository root.
  out.push(resolve(here, "..", "..", "target", "release", BIN));
  return out;
}

function executable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export const SETUP_TEXT = [
  "The freeq voice bridge (freeq-claude-mcp) is not built on this machine.",
  "From a clone of https://github.com/freeq-irc/freeq run:",
  "",
  "    freeq-cc/scripts/install-av.sh",
  "",
  "It builds the bridge with cargo (Rust 1.85+) and puts it in ~/.freeq/cc/bin.",
  "Or point FREEQ_AV_BIN at a binary you built. Then restart Claude Code.",
  "Voice also needs GROQ_API_KEY (speech to text) and ELEVENLABS_API_KEY (text to speech) in the environment.",
].join("\n");

async function standIn(): Promise<void> {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");
  const server = new Server({ name: "freeq-av", version: "0.0.0" }, { capabilities: { tools: {} }, instructions: SETUP_TEXT });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "av_setup",
        description: "freeq voice calls are not set up on this machine: call this for how to build the voice bridge.",
        inputSchema: { type: "object", properties: {} },
      },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: SETUP_TEXT }] }));
  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const bin = avCandidates().find(executable);
  if (bin) {
    const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
    child.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => child.kill(sig));
  } else {
    await standIn();
  }
}
