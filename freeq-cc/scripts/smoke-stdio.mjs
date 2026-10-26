#!/usr/bin/env node
/**
 * Smoke test of the built entry, as Claude Code starts it: run
 * `dist/server.js` over stdio with an empty state directory, send
 * `initialize`, and check that the answer declares the channel capability
 * and that stdout carried nothing but JSON-RPC. Exits non-zero on failure.
 */
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const entry = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "server.js");
const dir = mkdtempSync(join(process.env.SMOKE_DIR ?? tmpdir(), "freeq-cc-smoke-"));

const child = spawn(process.execPath, [entry], {
  env: { ...process.env, FREEQ_CC_DIR: dir, CLAUDE_PROJECT_DIR: dir },
  stdio: ["pipe", "pipe", "pipe"],
});
const exited = new Promise((r) => child.once("exit", r));
let stdout = "";
let stderr = "";
child.stdout.on("data", (d) => (stdout += String(d)));
child.stderr.on("data", (d) => (stderr += String(d)));

child.stdin.write(
  `${JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: { experimental: { "claude/channel": {} } },
      clientInfo: { name: "freeq-cc-smoke", version: "0" },
    },
  })}\n`,
);

const deadline = Date.now() + 10_000;
while (Date.now() < deadline && !stdout.includes('"id":1')) await new Promise((r) => setTimeout(r, 50));
await new Promise((r) => setTimeout(r, 500));
child.stdin.end();
await exited;

const fail = (why) => {
  console.error(`freeq-cc smoke: FAIL — ${why}\n--- stdout\n${stdout}\n--- stderr\n${stderr}`);
  process.exit(1);
};

const lines = stdout.split("\n").filter((l) => l.trim());
let init;
for (const line of lines) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    fail(`stdout carried a line that is not JSON: ${line.slice(0, 120)}`);
  }
  if (msg.jsonrpc !== "2.0") fail(`stdout carried JSON that is not JSON-RPC: ${line.slice(0, 120)}`);
  if (msg.id === 1) init = msg;
}
if (!init) fail("no answer to initialize");
if (!init.result?.capabilities?.experimental?.["claude/channel"]) {
  fail("the answer to initialize does not declare experimental['claude/channel']");
}
console.log(`freeq-cc smoke: ok — ${lines.length} JSON-RPC line(s) on stdout, claude/channel declared`);
