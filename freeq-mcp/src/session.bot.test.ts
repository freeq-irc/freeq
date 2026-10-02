/**
 * The authenticated path end to end through a real bot-kit bot, over a mock
 * socket: the certificate goes to the server, and whoami reads the server's
 * verdict. Bot state goes under a temporary HOME, not the real one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./config.js";
import { FreeqSession } from "./session.js";

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  CONNECTING = 0;
  OPEN = 1;
  CLOSING = 2;
  CLOSED = 3;
  static instances: MockWebSocket[] = [];
  readyState = 0;
  bufferedAmount = 0;
  sent: string[] = [];
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  constructor(readonly url: string) {
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }
  send(data: string): void {
    if (this.readyState === 1) this.sent.push(data);
  }
  close(): void {
    this.readyState = 3;
    this.onclose?.({});
  }
  recv(line: string): void {
    this.onmessage?.({ data: line + "\r\n" });
  }
}

const flush = async (): Promise<void> => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
};

let home: string;
let realWebSocket: unknown;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "freeq-mcp-home-"));
  vi.stubEnv("HOME", home);
  MockWebSocket.instances = [];
  realWebSocket = globalThis.WebSocket;
  (globalThis as { WebSocket: unknown }).WebSocket = MockWebSocket;
});
afterEach(async () => {
  (globalThis as { WebSocket: unknown }).WebSocket = realWebSocket;
  vi.unstubAllEnvs();
  await rm(home, { recursive: true, force: true });
});

describe("an owner-configured session", () => {
  it("sends its certificate and reports the server's verdict", async () => {
    const session = new FreeqSession(
      loadConfig({
        FREEQ_SERVER: "http://127.0.0.1:6668",
        FREEQ_OWNER_DID: "did:plc:owner",
        FREEQ_NICK: "mcp-test",
      }),
    );
    const connecting = session.connect();
    // Creating the bot reads and writes its key files, which takes as long
    // as the machine takes; wait for the socket itself.
    while (MockWebSocket.instances.length === 0) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const ws = MockWebSocket.instances[0]!;
    await flush();
    ws.recv(":irc.test CAP * LS :");
    await flush();
    ws.recv(":irc.test 001 mcp-test :Welcome");
    await flush();
    ws.recv(":irc.test 376 mcp-test :End of MOTD");
    // A real server issues the REST bearer after login; the session waits
    // (bounded) for it to publish the room pre-key before connect resolves.
    ws.recv(":irc.test NOTICE mcp-test :API-BEARER test-bearer");
    await connecting;
    await flush();

    expect(ws.sent.some((l) => l.startsWith("PROVENANCE "))).toBe(true);
    expect(session.status().ownerVerified).toBe(false);

    ws.recv(":irc.test NOTICE mcp-test :Provenance verified: Owner's agent record at://x names this bot");
    await flush();
    const s = session.status();
    expect(s.ownerVerified).toBe(true);
    expect(s.note).toContain("Owner's agent record at://x names this bot");

    // Closing stops the bot, not only its client: bot-kit's stop() is what
    // clears its heartbeat, its NOTICE reader and its wait, and it is the
    // only path that sends PRESENCE offline.
    await session.close();
    expect(ws.sent.some((l) => l.startsWith("PRESENCE ") && l.includes("offline"))).toBe(true);
  });
});
