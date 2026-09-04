import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpStdioClient } from "./mcp-stdio.js";

/**
 * A tiny MCP server in a shell script: enough of the protocol to prove the
 * client's handshake, correlation, tool results and error handling, without
 * depending on the Rust binary being built.
 */
async function fakeServer(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "mcp-fake-"));
  const path = join(dir, "server.mjs");
  await writeFile(
    path,
    `
import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
const send = (o) => process.stdout.write(JSON.stringify(o) + "\\n");
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "0" } } });
  else if (m.method === "notifications/initialized") { /* ignore */ }
  else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo", inputSchema: { type: "object" } }, { name: "boom", inputSchema: { type: "object" } }, { name: "slow", inputSchema: { type: "object" } }] } });
  else if (m.method === "tools/call") {
    const { name, arguments: a } = m.params;
    if (name === "echo") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "you said " + a.text }] } });
    else if (name === "boom") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "no such thing" }], isError: true } });
    else if (name === "slow") setTimeout(() => send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "late" }] } }), 400);
    else if (name === "die") process.exit(3);
    else send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown tool " + name } });
  }
});
`,
  );
  await chmod(path, 0o755);
  return path;
}

describe("McpStdioClient", () => {
  it("completes the handshake and discovers tools", async () => {
    const server = await fakeServer();
    const c = await McpStdioClient.start({ command: process.execPath, args: [server] });
    expect(c.tools.map((t) => t.name)).toEqual(["echo", "boom", "slow"]);
    await c.close();
  });

  it("correlates concurrent calls by id, whatever order they answer in", async () => {
    const server = await fakeServer();
    const c = await McpStdioClient.start({ command: process.execPath, args: [server] });
    // `slow` answers 400ms later; `echo` answers at once. Both must land on
    // the right promise.
    const [slow, fast] = await Promise.all([
      c.call("slow"),
      c.call("echo", { text: "hi" }),
    ]);
    expect(McpStdioClient.text(slow)).toBe("late");
    expect(McpStdioClient.text(fast)).toBe("you said hi");
    await c.close();
  });

  it("returns a tool's own failure as isError, and a protocol error as a throw", async () => {
    const server = await fakeServer();
    const c = await McpStdioClient.start({ command: process.execPath, args: [server] });
    const r = await c.call("boom");
    expect(r.isError).toBe(true);
    expect(McpStdioClient.text(r)).toBe("no such thing");
    await expect(c.call("nope")).rejects.toThrow(/unknown tool nope/);
    await c.close();
  });

  it("times out a call that never answers, per call", async () => {
    const server = await fakeServer();
    const c = await McpStdioClient.start({ command: process.execPath, args: [server] });
    await expect(c.call("slow", {}, 50)).rejects.toThrow(/timed out after 50ms/);
    await c.close();
  });

  it("rejects in-flight calls when the server dies, and reports the exit", async () => {
    const server = await fakeServer();
    let exited: number | null | undefined;
    const c = await McpStdioClient.start({
      command: process.execPath,
      args: [server],
      onExit: (code) => (exited = code),
    });
    // A crash mid-call: the server exits with the request unanswered.
    const p = c.call("die");
    await expect(p).rejects.toThrow(/exited \(code 3\)/);
    expect(c.alive).toBe(false);
    expect(exited).toBe(3);
  });
});
