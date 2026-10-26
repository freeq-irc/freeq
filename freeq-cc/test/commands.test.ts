import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { COMMANDS, commandFile, parseTyped } from "../src/commands.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("parseTyped: a /freeq:<sub> line as the person typed it", () => {
  it("takes the subcommand and its words", () => {
    expect(parseTyped("/freeq:join #dev")).toEqual({ name: "join", line: "join #dev", yes: false });
    expect(parseTyped("/freeq:status")).toEqual({ name: "status", line: "status", yes: false });
    expect(parseTyped("  /freeq:login did:plc:x  wss://irc.example.test/irc ")).toEqual({
      name: "login",
      line: "login did:plc:x wss://irc.example.test/irc",
      yes: false,
    });
  });

  it("keeps every word of a note or a reason", () => {
    expect(parseTyped("/freeq:progress 01JT ported the lexer")?.line).toBe("progress 01JT ported the lexer");
    expect(parseTyped("/freeq:decline 01JT not my area")?.line).toBe("decline 01JT not my area");
  });

  it("takes a trailing yes as the confirmation, only where a subcommand asks for one", () => {
    expect(parseTyped("/freeq:trust did:plc:x request yes")).toEqual({ name: "trust", line: "trust did:plc:x request", yes: true });
    expect(parseTyped("/freeq:takeover YES")).toEqual({ name: "takeover", line: "takeover", yes: true });
    expect(parseTyped("/freeq:progress 01JT yes")).toEqual({ name: "progress", line: "progress 01JT yes", yes: false });
  });

  it("leaves everything else alone", () => {
    expect(parseTyped("/freeq:nope")).toBeUndefined();
    expect(parseTyped("please /freeq:join #dev")).toBeUndefined();
    expect(parseTyped("/freeq:joinx")).toBeUndefined();
    expect(parseTyped("/plugin:freeq:freeq:join #dev")).toBeUndefined();
    expect(parseTyped("hello")).toBeUndefined();
  });
});

describe("the plugin's command files", () => {
  it("are one per subcommand, each as commandFile() writes it", () => {
    const files = readdirSync(join(root, "commands")).sort();
    expect(files).toEqual(COMMANDS.map((c) => `${c.name}.md`).sort());
    for (const c of COMMANDS) {
      expect(readFileSync(join(root, "commands", `${c.name}.md`), "utf8")).toBe(commandFile(c));
    }
  });

  it("show the arguments and keep the model from running them", () => {
    const login = commandFile(COMMANDS.find((c) => c.name === "login")!);
    expect(login).toContain('argument-hint: "<did> [server]"');
    expect(login).toContain("disable-model-invocation: true");
    expect(login).toContain("Do not run any tool");
  });
});

describe("the plugin's manifest and hooks", () => {
  it("names the plugin freeq and starts dist/server.js from the plugin root", () => {
    const manifest = JSON.parse(readFileSync(join(root, ".claude-plugin", "plugin.json"), "utf8"));
    expect(manifest.name).toBe("freeq");
    expect(manifest.mcpServers.freeq).toEqual({ command: "node", args: ["${CLAUDE_PLUGIN_ROOT}/dist/server.js"] });
    expect(manifest.channels).toEqual([{ server: "freeq" }]);
  });

  it("points the three hooks at the plugin's server", () => {
    const { hooks } = JSON.parse(readFileSync(join(root, "hooks", "hooks.json"), "utf8"));
    expect(Object.keys(hooks)).toEqual(["UserPromptSubmit", "PreToolUse", "Stop"]);
    for (const event of Object.keys(hooks)) {
      const h = hooks[event][0].hooks[0];
      expect(h).toMatchObject({ type: "mcp_tool", server: "plugin:freeq:freeq", tool: "freeq_hook" });
      expect(h.input.hook_event_name).toBe(event);
    }
    expect(hooks.PreToolUse[0].matcher).toBe("*");
    // The freeq tool's work line needs its action and target, as freeq-pi's does.
    expect(hooks.PreToolUse[0].hooks[0].input).toMatchObject({
      action: "${tool_input.action}",
      to: "${tool_input.to}",
    });
  });
});
