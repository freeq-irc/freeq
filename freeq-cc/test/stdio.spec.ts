/**
 * The built entry over real stdio: stdout carries nothing but JSON-RPC,
 * even while the SDK is logging a connection it cannot make. Runs
 * `dist/server.js`, so `npm run build` comes first (as in CI).
 */
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const entry = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "server.js");

function rpc(id: number, method: string, params: Record<string, unknown> = {}): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`;
}

describe("freeq-cc over stdio", () => {
  it("writes only JSON-RPC to stdout while connecting and answering", async () => {
    const root = mkdtempSync(join(tmpdir(), "freeq-cc-stdio-"));
    const dir = join(root, "cc");
    const project = join(root, "proj");
    mkdirSync(dir, { recursive: true });
    mkdirSync(project, { recursive: true });
    // A known project and a server nothing listens on: it tries to connect,
    // fails, and the SDK logs about it.
    writeFileSync(
      join(dir, "freeq.json"),
      JSON.stringify({
        ownerDid: "did:plc:owner",
        server: "ws://127.0.0.1:9/irc",
        install: "stdio1234",
        projects: { proj: { channels: ["#work"] } },
      }),
    );

    const child = spawn(process.execPath, [entry], {
      env: { ...process.env, HOME: root, FREEQ_CC_DIR: dir, CLAUDE_PROJECT_DIR: project },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const exited = new Promise((r) => child.once("exit", r));
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));

    child.stdin.write(
      rpc(1, "initialize", {
        protocolVersion: "2025-06-18",
        capabilities: { experimental: { "claude/channel": {} } },
        clientInfo: { name: "stdio-test", version: "0" },
      }),
    );
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    child.stdin.write(rpc(2, "tools/list"));
    child.stdin.write(rpc(3, "tools/call", { name: "freeq_hook", arguments: { hook_event_name: "UserPromptSubmit", prompt: "/freeq:status" } }));

    // Answers to all three, and time for the failing connect to log.
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && !(stdout.includes('"id":3') && stderr.length > 0)) {
      await new Promise((r) => setTimeout(r, 50));
    }
    await new Promise((r) => setTimeout(r, 500));
    child.stdin.end();
    await exited;

    const lines = stdout.split("\n").filter((l) => l.trim());
    for (const line of lines) {
      const msg = JSON.parse(line) as { jsonrpc?: string };
      expect(msg.jsonrpc).toBe("2.0");
    }
    const init = lines.map((l) => JSON.parse(l)).find((m) => m.id === 1);
    expect(init.result.capabilities.experimental["claude/channel"]).toEqual({});
    expect(lines.some((l) => l.includes('"id":3'))).toBe(true);
    // The logging went somewhere, and it was not stdout.
    expect(stderr).toContain("freeq-cc");
  }, 20_000);
});
