/**
 * Start freeq-cc's channel server against a fake bot, and connect an MCP
 * client to it the way Claude Code does, over an in-memory transport.
 */
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { ClientCapabilities } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { createChannel } from "../src/channel.js";
import { FakeBot } from "./fake-bot.js";

export const OWNER = "did:plc:owner";
export const PEER = "did:plc:peer";

/** A config that connects on start in project `proj`. */
export function baseConfig(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ownerDid: OWNER,
    server: "ws://test.invalid/irc",
    install: "test1234",
    channels: ["#work"],
    projects: { proj: { channels: ["#work"] } },
    trust: {},
    ...over,
  };
}

/** Let fire-and-forget work (inbound handlers, notifications) finish. */
export async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  await new Promise((r) => setTimeout(r, 5));
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

const ChannelEvent = z.object({
  method: z.literal("notifications/claude/channel"),
  params: z.object({ content: z.string(), meta: z.record(z.string()).optional() }),
});

const PermissionVerdict = z.object({
  method: z.literal("notifications/claude/channel/permission"),
  params: z.object({ request_id: z.string(), behavior: z.string() }),
});

export interface StartOptions {
  /** Written as `<agentDir>/freeq.json`; omit for a fresh install. */
  config?: Record<string, unknown>;
  /** What the client declares in `initialize`. */
  capabilities?: ClientCapabilities;
  /** Declared by the client as its experimental capabilities too. */
  experimental?: Record<string, object>;
}

export async function startChannel(opts: StartOptions = {}) {
  const root = mkdtempSync(join(tmpdir(), "freeq-cc-test-"));
  const agentDir = join(root, "cc");
  const cwd = join(root, "proj");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  if (opts.config) writeFileSync(join(agentDir, "freeq.json"), JSON.stringify(opts.config));

  const bot = new FakeBot();
  const logs: string[] = [];
  const channel = await createChannel({
    agentDir,
    cwd: () => cwd,
    botFactory: async (o) => {
      bot.mention = o.mention.matcher;
      return bot;
    },
    log: (line) => logs.push(line),
  });

  const client = new Client(
    { name: "claude-code-test", version: "0.0.0" },
    { capabilities: { ...(opts.capabilities ?? {}), experimental: opts.experimental ?? { "claude/channel": {} } } },
  );
  const events: Array<{ content: string; meta?: Record<string, string> }> = [];
  const verdicts: Array<{ request_id: string; behavior: string }> = [];
  client.setNotificationHandler(ChannelEvent, (n) => void events.push(n.params));
  client.setNotificationHandler(PermissionVerdict, (n) => void verdicts.push(n.params));

  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await channel.server.connect(serverSide);
  await client.connect(clientSide);
  await channel.started;
  await settle();

  const text = (r: { content?: unknown }): string =>
    ((r.content as Array<{ type: string; text?: string }>) ?? [])
      .filter((c) => c.type === "text")
      .map((c) => c.text)
      .join("\n");

  return {
    root,
    agentDir,
    cwd,
    bot,
    channel,
    client,
    events,
    verdicts,
    logs,
    /** A direct message from `from`, whose server-resolved DID is `did`. */
    async dm(from: string, did: string | null, message: string): Promise<void> {
      bot.emit("message", from, { from, text: message, isSelf: false, tags: did ? { account: did } : {} });
      await settle();
    },
    /** A channel message. */
    async say(ch: string, from: string, did: string | null, message: string): Promise<void> {
      bot.emit("message", ch, { from, text: message, isSelf: false, tags: did ? { account: did } : {} });
      await settle();
    },
    /** A peer's `pi_ask`, with the server-resolved DID. */
    async ask(from: string, did: string, question: string, req = "req-1"): Promise<void> {
      bot.emit("coordinationEvent", {
        eventType: "pi_ask",
        from,
        did,
        channel: from,
        payload: { req, q: question },
        tags: { account: did },
      });
      await settle();
    },
    /** Call the `freeq` tool and return its text. */
    async tool(args: Record<string, unknown>): Promise<string> {
      const r = await client.callTool({ name: "freeq", arguments: args });
      await settle();
      return text(r);
    },
    /** Call `freeq_hook` as a Claude Code `mcp_tool` hook would, and parse its answer. */
    async hook(input: Record<string, unknown>): Promise<Record<string, unknown>> {
      const r = await client.callTool({ name: "freeq_hook", arguments: input });
      await settle();
      return JSON.parse(text(r)) as Record<string, unknown>;
    },
    /**
     * Type a `/freeq:<sub>` line, as the UserPromptSubmit hook sees it, and
     * return what the hook hands Claude to show.
     */
    async command(typed: string): Promise<string> {
      const out = await this.hook({ hook_event_name: "UserPromptSubmit", prompt: typed });
      const specific = out.hookSpecificOutput as { additionalContext?: string } | undefined;
      return String(specific?.additionalContext ?? "");
    },
    async close(): Promise<void> {
      await channel.stop();
      await client.close();
    },
  };
}
