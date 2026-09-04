/**
 * A minimal MCP client over stdio, so pi can drive an MCP server it does not
 * otherwise know how to talk to.
 *
 * pi deliberately ships without built-in MCP. The freeq AV bridge
 * (`freeq-claude-mcp`, Rust) is an MCP server: it joins a voice call, runs
 * STT, speaks via TTS, and projects a visual tile — and until now only Claude
 * Code could drive it, because only Claude Code speaks MCP. This is the ~100
 * lines that let pi do the same, and nothing more: initialize, list tools,
 * call a tool. No resources, no prompts, no sampling, no SSE.
 *
 * The protocol is JSON-RPC 2.0, one message per line, request ids correlated
 * by the client. The server may interleave notifications; those are ignored
 * unless a handler is registered.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface McpToolResult {
  content: Array<{ type: string; text?: string; [k: string]: unknown }>;
  structuredContent?: unknown;
  isError?: boolean;
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export interface McpStdioOptions {
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  /** Per-call timeout. Long-polls (`freeq_listen`) pass their own. */
  defaultTimeoutMs?: number;
  /** Diagnostic output from the server's stderr. */
  onStderr?: (line: string) => void;
  /** Called when the server process exits. */
  onExit?: (code: number | null) => void;
}

export class McpStdioClient {
  #proc: ChildProcessWithoutNullStreams;
  #pending = new Map<number, Pending>();
  #nextId = 1;
  #closed = false;
  #opts: McpStdioOptions;
  #tools: McpTool[] = [];

  private constructor(proc: ChildProcessWithoutNullStreams, opts: McpStdioOptions) {
    this.#proc = proc;
    this.#opts = opts;
    createInterface({ input: proc.stdout }).on("line", (line) => this.#onLine(line));
    if (opts.onStderr) {
      createInterface({ input: proc.stderr }).on("line", (l) => opts.onStderr?.(l));
    }
    proc.on("exit", (code) => {
      this.#closed = true;
      for (const [, p] of this.#pending) {
        clearTimeout(p.timer);
        p.reject(new Error(`MCP server exited (code ${code}) with the call in flight`));
      }
      this.#pending.clear();
      opts.onExit?.(code);
    });
  }

  /** Spawn the server and complete the MCP handshake. */
  static async start(opts: McpStdioOptions): Promise<McpStdioClient> {
    const proc = spawn(opts.command, opts.args ?? [], {
      env: { ...process.env, ...(opts.env ?? {}) },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const client = new McpStdioClient(proc, opts);
    await client.#request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "freeq-pi", version: "0.1.0" },
    });
    client.#notify("notifications/initialized", {});
    const listed = (await client.#request("tools/list", {})) as { tools?: McpTool[] };
    client.#tools = listed.tools ?? [];
    return client;
  }

  get tools(): readonly McpTool[] {
    return this.#tools;
  }

  get alive(): boolean {
    return !this.#closed;
  }

  /** Call a tool. A tool's own failure comes back as `isError`, not a throw. */
  async call(name: string, args: Record<string, unknown> = {}, timeoutMs?: number): Promise<McpToolResult> {
    const r = (await this.#request("tools/call", { name, arguments: args }, timeoutMs)) as McpToolResult;
    return r;
  }

  /** The first text block of a result, which is what most of these tools return. */
  static text(r: McpToolResult): string {
    return r.content
      .filter((c) => c.type === "text" && typeof c.text === "string")
      .map((c) => c.text as string)
      .join("\n");
  }

  /** Stop the server. Idempotent. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    try {
      this.#proc.stdin.end();
    } catch {
      /* already gone */
    }
    const exited = new Promise<void>((resolve) => this.#proc.once("exit", () => resolve()));
    const timer = setTimeout(() => this.#proc.kill("SIGKILL"), 2000);
    await exited;
    clearTimeout(timer);
  }

  #request(method: string, params: unknown, timeoutMs = this.#opts.defaultTimeoutMs ?? 30_000): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error("MCP server is not running"));
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MCP ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  #notify(method: string, params: unknown): void {
    if (this.#closed) return;
    this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  #onLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg: { id?: number; result?: unknown; error?: { message?: string; code?: number } };
    try {
      msg = JSON.parse(trimmed);
    } catch {
      return; // not JSON-RPC; the server logs to stderr, but be tolerant
    }
    if (typeof msg.id !== "number") return; // notification
    const p = this.#pending.get(msg.id);
    if (!p) return;
    this.#pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) p.reject(new Error(msg.error.message ?? `MCP error ${msg.error.code ?? "?"}`));
    else p.resolve(msg.result);
  }
}
