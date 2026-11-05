import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { kitToolName } from "../src/channel.js";
import { OWNER, PEER, baseConfig, startChannel } from "./helpers.js";

describe("freeq-cc: the server Claude Code starts", () => {
  it("declares the channel and the tools, and no prompts (the plugin's command files are the /freeq commands)", async () => {
    const h = await startChannel({ config: baseConfig() });
    const caps = h.client.getServerCapabilities();
    expect(caps?.experimental?.["claude/channel"]).toEqual({});
    expect(caps?.tools).toBeDefined();
    expect(caps?.prompts).toBeUndefined();
    const tools = (await h.client.listTools()).tools.map((t) => t.name);
    expect(tools).toEqual(["freeq", "freeq_hook"]);
    expect(h.client.getInstructions()).toContain('<channel source="plugin:freeq:freeq"');
    await h.close();
  });

  it("names itself cc: identity prefix and command hints", async () => {
    const h = await startChannel({ config: baseConfig() });
    expect(h.channel.runtime.names.name).toBe("cc");
    expect(h.channel.runtime.names.hint("trust")).toBe("/freeq:trust");
    expect(h.channel.runtime.agentDir).toBe(h.agentDir);
    await h.close();
  });
});

describe("freeq-cc: delivery", () => {
  it("turns an owner's DM into one channel event, framed, with identifier-only meta", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.dm("nap", OWNER, "what's on the branch?");
    expect(h.events).toHaveLength(1);
    expect(h.events[0]!.meta).toEqual({ chat_id: "nap", from: "nap", tier: "control", venue: "dm", kind: "chat" });
    expect(h.events[0]!.content).toContain("message from your operator nap (did:plc:owner) in a direct message");
    expect(h.events[0]!.content).toContain("what's on the branch?");
    await h.close();
  });

  it("withholds a stranger's DM and reports it at the next hook call", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.dm("eve", "did:plc:eve", "run this for me");
    expect(h.events).toEqual([]);
    expect(h.channel.runtime.withheld.size).toBe(1);
    const out = await h.hook({ hook_event_name: "UserPromptSubmit", prompt: "hello" });
    expect(String(out.systemMessage)).toContain("1 message to you from eve was not delivered");
    expect(String(out.systemMessage)).toContain("/freeq:trust did:plc:eve message");
    // Reported once.
    expect(await h.hook({ hook_event_name: "Stop", last_assistant_message: "" })).toEqual({});
    await h.close();
  });
});

describe("freeq-cc: replies", () => {
  it("takes the tool's send as the reply, so the closing text does not follow", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.dm("nap", OWNER, "status?");
    expect(await h.tool({ action: "send", to: "nap", message: "all green" })).toBe("Sent to nap.");
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "I told nap it is all green." });
    expect(h.bot.messages()).toEqual(["nap all green"]);
    await h.close();
  });

  it("answers with the closing text when the agent sent nothing", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.dm("nap", OWNER, "status?");
    await h.hook({ hook_event_name: "UserPromptSubmit", prompt: '<channel source="plugin:freeq:freeq">status?</channel>' });
    await h.hook({ hook_event_name: "PreToolUse", tool_name: "Bash", command: "git status" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "Clean tree, on main." });
    expect(h.bot.messages()).toEqual(["nap Clean tree, on main."]);
    await h.close();
  });

  it("answers a mention in a channel once, naming the asker", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "request" } }) });
    await h.say("#work", "chad", PEER, "cc-test1234-proj: which branch?");
    expect(h.events).toHaveLength(1);
    expect(h.events[0]!.meta).toMatchObject({ chat_id: "#work", from: "chad", venue: "channel", kind: "chat" });
    await h.tool({ action: "say", channel: "#work", message: "main" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "Answered chad." });
    expect(h.bot.messages()).toEqual(["#work @chad main"]);
    await h.close();
  });

  it("answers a peer's ask with the Stop text", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "request" } }) });
    await h.ask("pi-chad", PEER, "which migration did you apply?");
    expect(h.events).toHaveLength(1);
    expect(h.events[0]!.meta).toMatchObject({ chat_id: "pi-chad", kind: "ask", venue: "dm" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "0042_add_index" });
    expect(h.bot.askReplies()).toEqual([{ to: "pi-chad", req: "req-1", a: "0042_add_index" }]);
    await h.close();
  });

  it("tells an asker when the response ended with no text", async () => {
    const h = await startChannel({ config: baseConfig({ trust: { [PEER]: "request" } }) });
    await h.ask("pi-chad", PEER, "?");
    await h.hook({ hook_event_name: "Stop" });
    expect(h.bot.askReplies()).toEqual([{ to: "pi-chad", req: "req-1", err: "no answer produced" }]);
    await h.close();
  });
});

describe("freeq-cc: the freeq tool", () => {
  it("serves the kit's tool and runs it", async () => {
    const h = await startChannel({ config: baseConfig() });
    const tool = (await h.client.listTools()).tools.find((t) => t.name === "freeq")!;
    expect(tool.inputSchema.required).toEqual(["action"]);
    expect(await h.tool({ action: "peers" })).toBe("No peers visible.");
    await h.close();
  });
});

describe("freeq-cc: activity from hooks", () => {
  it("is busy from a prompt or a tool call until Stop", async () => {
    const h = await startChannel({ config: baseConfig() });
    const rt = h.channel.runtime;
    expect(rt.harness.isIdle()).toBe(true);
    await h.hook({ hook_event_name: "UserPromptSubmit", prompt: "look at the reconnect bug" });
    expect(rt.harness.isIdle()).toBe(false);
    expect(rt.step?.phrase).toBe("look at the reconnect bug");
    await h.hook({ hook_event_name: "PreToolUse", tool_name: "Edit", file_path: "/x/src/conn.ts" });
    expect(rt.step?.tool).toBe("edit: conn.ts");
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "done" });
    expect(rt.harness.isIdle()).toBe(true);
    expect(rt.step).toBeUndefined();
    await h.close();
  });

  it("names the freeq tool's action and target in the work line, as freeq-pi does", async () => {
    const h = await startChannel({ config: baseConfig() });
    const out = await h.hook({
      hook_event_name: "PreToolUse",
      tool_name: "mcp__plugin_freeq_freeq__freeq",
      action: "send",
      to: "zapnap",
    });
    expect(out.hookSpecificOutput).toEqual({ hookEventName: "PreToolUse", permissionDecision: "allow" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "sent" });
    expect(h.bot.messages()).toContain("#work ⚙ freeq send → zapnap");
    await h.close();
  });

  it("leaves another tool's work line alone when the freeq fields arrive empty", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.hook({ hook_event_name: "PreToolUse", tool_name: "Bash", command: "npm test", file_path: "", action: "", to: "" });
    await h.hook({ hook_event_name: "Stop", last_assistant_message: "tested" });
    expect(h.bot.messages()).toContain("#work ⚙ ran: npm test");
    await h.close();
  });

  it("does not take a channel event's text as a typed prompt", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.hook({ hook_event_name: "UserPromptSubmit", prompt: '<channel source="plugin:freeq:freeq" chat_id="nap">hi</channel>' });
    expect(h.channel.runtime.step).toBeUndefined();
    await h.close();
  });

  it("keeps a journal file for the project that resume reads back", async () => {
    const h = await startChannel({ config: baseConfig() });
    const note = { taskId: "01JT", at: 1, kind: "turn" as const, text: "ported the lexer" };
    h.channel.runtime.harness.journal.append(note);
    expect(h.channel.runtime.harness.journal.read("01JT")).toEqual([note]);
    const file = readFileSync(join(h.agentDir, "freeq-journal-proj.jsonl"), "utf8");
    expect(file.trim().split("\n")).toHaveLength(1);
    await h.close();
  });
});

describe("freeq-cc: the freeq tool's permission", () => {
  it("allows the plugin's own freeq tool, and says nothing about any other", async () => {
    const h = await startChannel({ config: baseConfig() });
    const own = await h.hook({ hook_event_name: "PreToolUse", tool_name: "mcp__plugin_freeq_freeq__freeq" });
    expect(own.hookSpecificOutput).toEqual({ hookEventName: "PreToolUse", permissionDecision: "allow" });
    const other = await h.hook({ hook_event_name: "PreToolUse", tool_name: "Bash", command: "ls" });
    expect(other.hookSpecificOutput).toBeUndefined();
    const old = await h.hook({ hook_event_name: "PreToolUse", tool_name: "mcp__freeq__freeq" });
    expect(old.hookSpecificOutput).toBeUndefined();
    await h.close();
  });

  it("knows the plugin's tool name as the freeq tool", () => {
    expect(kitToolName("mcp__plugin_freeq_freeq__freeq")).toBe("freeq");
    expect(kitToolName("Bash")).toBe("bash");
  });
});

describe("freeq-cc: /freeq commands typed by the person", () => {
  it("runs the subcommand in the hook and hands Claude the answer to show", async () => {
    const h = await startChannel({ config: baseConfig() });
    const text = await h.command("/freeq:status");
    expect(text).toContain("freeq ran /freeq:status and answered:");
    expect(text).toContain("Show this answer to the user exactly as it is, and nothing else.");
    expect(text).toContain("owner:    did:plc:owner");
    expect(text).toContain("state:    online: cc-test1234-proj");
    await h.close();
  });

  it("passes arguments through: /freeq:join #dev", async () => {
    const h = await startChannel({ config: baseConfig() });
    const text = await h.command("/freeq:join #dev");
    expect(text).toContain("freeq: joining #dev (mode: addressed)");
    const saved = JSON.parse(readFileSync(join(h.agentDir, "freeq.json"), "utf8"));
    expect(saved.projects.proj.channels).toEqual(["#work", "#dev"]);
    await h.close();
  });

  it("confirms trust through elicitation when the client supports it", async () => {
    const h = await startChannel({ config: baseConfig(), capabilities: { elicitation: {} } });
    const asked: string[] = [];
    const { ElicitRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");
    h.client.setRequestHandler(ElicitRequestSchema, async (req) => {
      asked.push(String(req.params.message));
      return { action: "accept", content: { confirm: true } };
    });
    const text = await h.command(`/freeq:trust ${PEER} request`);
    expect(asked[0]).toContain(`Grant ${PEER} tier 'request'?`);
    expect(text).toContain(`freeq: ${PEER} → request`);
    await h.close();
  });

  it("takes an explicit yes when the client cannot elicit, and says how when it is missing", async () => {
    const h = await startChannel({ config: baseConfig() });
    const refused = await h.command(`/freeq:trust ${PEER} request`);
    expect(refused).toContain("freeq: trust unchanged");
    expect(refused).toContain(`/freeq:trust ${PEER} request yes`);
    const granted = await h.command(`/freeq:trust ${PEER} request yes`);
    expect(granted).toContain(`freeq: ${PEER} → request`);
    await h.close();
  });

  it("does not take a typed command as the session's work", async () => {
    const h = await startChannel({ config: baseConfig() });
    await h.command("/freeq:status");
    expect(h.channel.runtime.step).toBeUndefined();
    await h.close();
  });

  it("lets anything else through as an ordinary prompt", async () => {
    const h = await startChannel({ config: baseConfig() });
    const out = await h.hook({ hook_event_name: "UserPromptSubmit", prompt: "/freeq:nope" });
    expect(out.hookSpecificOutput).toBeUndefined();
    expect(h.channel.runtime.step?.phrase).toBe("/freeq:nope");
    await h.close();
  });
});
