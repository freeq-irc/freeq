/**
 * Announce ordering: PROVENANCE goes out before any JOIN, and the JOINs wait
 * for the server's provenance NOTICE (bounded). Closes the documented
 * "JOIN races PROVENANCE" bug for every bot-kit consumer.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

type ReadyState = 0 | 1 | 2 | 3;

class MockWebSocket {
  static CONNECTING: ReadyState = 0;
  static OPEN: ReadyState = 1;
  static CLOSING: ReadyState = 2;
  static CLOSED: ReadyState = 3;
  static instances: MockWebSocket[] = [];

  CONNECTING: ReadyState = 0;
  OPEN: ReadyState = 1;
  CLOSING: ReadyState = 2;
  CLOSED: ReadyState = 3;

  url: string;
  readyState: ReadyState = 0;
  bufferedAmount = 0;
  sent: string[] = [];

  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string): void {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.({});
  }

  recv(line: string): void {
    this.onmessage?.({ data: line + "\r\n" });
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 8; i++) await Promise.resolve();
}

async function driveToReady(ws: MockWebSocket, nick: string): Promise<void> {
  await flushAsync();
  ws.recv(":srv CAP * LS :");
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.recv(`:srv 376 ${nick} :End of MOTD`);
  await flushAsync();
}

const idx = (lines: string[], prefix: string): number => lines.findIndex((l) => l.startsWith(prefix));

describe("announce ordering", () => {
  let root: string;
  let savedWait: number;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-order-"));
    const { FreeqBot } = await import("./bot.js");
    savedWait = FreeqBot.PROVENANCE_WAIT_MS;
  });
  afterEach(async () => {
    const { FreeqBot } = await import("./bot.js");
    FreeqBot.PROVENANCE_WAIT_MS = savedWait;
    await rm(root, { recursive: true, force: true });
  });

  it("JOINs only after the provenance NOTICE, and after PROVENANCE on the wire", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "order-bot", ownerDid: "did:plc:owner", nick: "order-bot", url: "wss://test/irc", root,
      channels: ["#gated", " #second "],
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "order-bot");
    await startPromise;

    // Announce is out; nothing has been joined yet — not by us, not by the SDK.
    expect(idx(ws.sent, "PROVENANCE ")).toBeGreaterThanOrEqual(0);
    expect(ws.sent.some((l) => l.startsWith("JOIN "))).toBe(false);

    ws.recv(":srv NOTICE order-bot :Provenance verified: delegation signed by owner");
    await flushAsync();

    const prov = idx(ws.sent, "PROVENANCE ");
    const join1 = idx(ws.sent, "JOIN #gated");
    const join2 = idx(ws.sent, "JOIN #second");
    expect(join1).toBeGreaterThan(prov);
    expect(join2).toBeGreaterThan(join1);
    // Exactly once.
    expect(ws.sent.filter((l) => l.startsWith("JOIN ")).length).toBe(2);

    await bot.stop();
  });

  it("an unverified or rejected provenance still releases the JOINs", async () => {
    const { FreeqBot } = await import("./bot.js");
    for (const notice of ["Provenance stored (unverified): no signature", "Provenance rejected: bad cert"]) {
      MockWebSocket.instances = [];
      const bot = await FreeqBot.create({
        name: `order-bot-${notice.length}`, ownerDid: "did:plc:owner", nick: "ob", url: "wss://test/irc", root,
        channels: ["#gated"],
      });
      const startPromise = bot.start();
      await flushAsync();
      const ws = MockWebSocket.instances[0]!;
      await driveToReady(ws, "ob");
      await startPromise;
      ws.recv(`:srv NOTICE ob :${notice}`);
      await flushAsync();
      expect(idx(ws.sent, "JOIN #gated")).toBeGreaterThan(idx(ws.sent, "PROVENANCE "));
      await bot.stop();
    }
  });

  it("JOINs anyway once the bounded wait elapses with no NOTICE", async () => {
    const { FreeqBot } = await import("./bot.js");
    FreeqBot.PROVENANCE_WAIT_MS = 60;
    const bot = await FreeqBot.create({
      name: "order-bot", ownerDid: "did:plc:owner", nick: "order-bot", url: "wss://test/irc", root,
      channels: ["#gated"],
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "order-bot");
    await startPromise;
    expect(ws.sent.some((l) => l.startsWith("JOIN "))).toBe(false);

    await new Promise((r) => setTimeout(r, 150));
    expect(idx(ws.sent, "JOIN #gated")).toBeGreaterThan(idx(ws.sent, "PROVENANCE "));
    // A late NOTICE does not JOIN a second time.
    ws.recv(":srv NOTICE order-bot :Provenance verified: late");
    await flushAsync();
    expect(ws.sent.filter((l) => l.startsWith("JOIN ")).length).toBe(1);

    await bot.stop();
  });

  it("stop() cancels a pending JOIN", async () => {
    const { FreeqBot } = await import("./bot.js");
    FreeqBot.PROVENANCE_WAIT_MS = 60;
    const bot = await FreeqBot.create({
      name: "order-bot", ownerDid: "did:plc:owner", nick: "order-bot", url: "wss://test/irc", root,
      channels: ["#gated"],
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "order-bot");
    await startPromise;
    await bot.stop();
    await new Promise((r) => setTimeout(r, 150));
    expect(ws.sent.some((l) => l.startsWith("JOIN "))).toBe(false);
  });

  it("a bot with no channels joins nothing (and the SDK's #freeq fallback stays off for DID sessions)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "order-bot", ownerDid: "did:plc:owner", nick: "order-bot", url: "wss://test/irc", root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "order-bot");
    await startPromise;
    ws.recv(":srv NOTICE order-bot :Provenance verified: ok");
    await flushAsync();
    expect(ws.sent.some((l) => l.startsWith("JOIN "))).toBe(false);
    await bot.stop();
  });

  it("exposes a lazily built RoomManager", async () => {
    const { FreeqBot } = await import("./bot.js");
    const { RoomManager } = await import("./rooms.js");
    const bot = await FreeqBot.create({
      name: "order-bot", ownerDid: "did:plc:owner", nick: "order-bot", url: "wss://test/irc", root,
    });
    const rooms = bot.rooms;
    expect(rooms).toBeInstanceOf(RoomManager);
    expect(bot.rooms).toBe(rooms);
    expect(rooms.channels()).toEqual([]);
  });
});
