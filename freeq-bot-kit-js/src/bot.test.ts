/** Unit tests for FreeqBot. Uses the same MockWebSocket pattern as
 *  freeq-sdk-js/src/client.test.ts so the FreeqClient inside FreeqBot
 *  has a real wire layer, just with no actual network. */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── WebSocket mock ────────────────────────────────────────────────────

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

/** Drive the mock socket through CAP negotiation, SASL bypass (we mock that
 *  off by setting an empty SASL config later), and the 001/376 numerics so
 *  FreeqClient emits `'ready'`. */
async function driveToReady(ws: MockWebSocket, nick: string): Promise<void> {
  await flushAsync();
  ws.recv(":srv CAP * LS :");
  await flushAsync();
  ws.recv(`:srv 001 ${nick} :Welcome`);
  await flushAsync();
  ws.recv(`:srv 376 ${nick} :End of MOTD`);
  await flushAsync();
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("FreeqBot.create", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("loads/creates identity + cert and constructs a FreeqClient", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    expect(bot.identity.isFresh).toBe(true);
    expect(bot.identity.did).toMatch(/^did:key:z/);
    expect(bot.delegation.bot_did).toBe(bot.identity.did);
    expect(bot.delegation.creator_did).toBe("did:plc:owner");
    expect(bot.stateDir).toBe(join(root, "test-bot"));
    expect(bot.client).toBeDefined();

    // Files were persisted with correct perms.
    const seedStat = await stat(join(bot.stateDir, "agent.key"));
    if (process.platform === "linux" || process.platform === "darwin") {
      expect(seedStat.mode & 0o777).toBe(0o600);
    }
    const cert = JSON.parse(await readFile(join(bot.stateDir, "delegation.json"), "utf8"));
    expect(cert.type).toBe("FreeqBotDelegation/v1");
  });

  it("rederives the same DID across runs", async () => {
    const { FreeqBot } = await import("./bot.js");
    const a = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const b = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    expect(b.identity.isFresh).toBe(false);
    expect(b.identity.did).toBe(a.identity.did);
    expect(b.delegation.bot_did).toBe(a.delegation.bot_did);
  });

  it("rejects when stored cert names a different owner", async () => {
    const { FreeqBot } = await import("./bot.js");
    await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    await expect(
      FreeqBot.create({
        name: "test-bot",
        ownerDid: "did:plc:somebody-else",
        nick: "test-bot",
        url: "wss://test/irc",
        root,
      }),
    ).rejects.toThrow(/creator_did/);
  });
});

describe("FreeqBot.start lifecycle", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("connects, awaits ready, and runs the announce sequence", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    // Announce sequence fired.
    const lines = ws.sent;
    expect(lines.some((l) => l.startsWith("PROVENANCE "))).toBe(true);
    expect(lines.some((l) => l.startsWith("AGENT REGISTER "))).toBe(true);
    expect(lines.some((l) => l.startsWith("PRESENCE "))).toBe(true);
    expect(lines.some((l) => l.startsWith("HEARTBEAT "))).toBe(true);

    await bot.stop();
  });

  it("includes AGENT MANIFEST when a manifest is provided", async () => {
    const { FreeqBot } = await import("./bot.js");
    const manifest = `
[agent]
display_name = "test-bot"
[provenance]
origin_type = "template"
creator_did = "did:plc:owner"
revocation_authority = "did:plc:owner"
[capabilities]
default = ["post_message"]
`;
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      manifest,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    expect(ws.sent.some((l) => l.startsWith("AGENT MANIFEST "))).toBe(true);
    await bot.stop();
  });

  it("omits AGENT MANIFEST when no manifest is provided", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    expect(ws.sent.some((l) => l.startsWith("AGENT MANIFEST "))).toBe(false);
    await bot.stop();
  });

  it("rejects start() on SASL authError", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start({ timeoutMs: 2000 });
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await flushAsync();
    // 904 is the SASL failure numeric.
    ws.recv(":srv 904 test-bot :SASL authentication failed");
    await expect(startPromise).rejects.toThrow(/SASL auth failed/);
  });

  it("rejects start() on disconnect before ready", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start({ timeoutMs: 2000 });
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    ws.close();
    await expect(startPromise).rejects.toThrow(/disconnected before ready/);
  });

  it("rejects start() on timeout", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start({ timeoutMs: 50 });
    // Don't drive to ready — let timeout fire.
    await expect(startPromise).rejects.toThrow(/timeout waiting for ready/);
  });

  it("refuses double start()", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const p1 = bot.start({ timeoutMs: 50 }).catch(() => {});
    await expect(bot.start()).rejects.toThrow(/more than once/);
    await p1;
  });
});

describe("FreeqBot.resolveSenderDid", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "bot-resolve-test-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("returns the account-tag DID without firing WHOIS", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "rb",
      ownerDid: "did:plc:owner",
      nick: "rb",
      url: "wss://test/irc",
      root,
    });
    // No connect() — the resolver works against the client's EventEmitter +
    // raw() surface regardless of WebSocket state. account-tag should
    // short-circuit before raw() would even be called.
    const did = await bot.resolveSenderDid({
      from: "alice",
      tags: { account: "did:plc:alice" },
    });
    expect(did).toBe("did:plc:alice");
  });

  it("returns null when account-tag is absent + WHOIS disabled (strict mode)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "rb-strict",
      ownerDid: "did:plc:owner",
      nick: "rb-strict",
      url: "wss://test/irc",
      root,
    });
    const did = await bot.resolveSenderDid(
      { from: "alice", tags: {} },
      { cache: false, whois: false },
    );
    expect(did).toBeNull();
  });
});

describe("FreeqBot.checkMention", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "bot-mention-test-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("matches @<nick> with the default matcher and returns stripped text", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
    });
    // Inject the nick directly — FreeqBot reads this.client.nick, which the
    // FreeqClient hasn't set yet because we never .connect()'d. Set it.
    (bot.client as unknown as { _nick: string })._nick = "yokota";

    const r = bot.checkMention("#foo", "@yokota help");
    expect(r.kind).toBe("respond");
    if (r.kind === "respond") expect(r.stripped).toBe("help");
  });

  it("ignores third-person bare-nick references (default matcher)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-bare",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
    });
    (bot.client as unknown as { _nick: string })._nick = "yokota";
    expect(bot.checkMention("#foo", "yokota wrote a great thing").kind).toBe(
      "ignore",
    );
  });

  it("returns cooldown for a second addressing within the window", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-cd",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
      mention: { cooldownMs: 60_000 },
    });
    (bot.client as unknown as { _nick: string })._nick = "yokota";

    const r1 = bot.checkMention("#foo", "@yokota first");
    expect(r1.kind).toBe("respond");
    const r2 = bot.checkMention("#foo", "@yokota second");
    expect(r2.kind).toBe("cooldown");
    if (r2.kind === "cooldown") expect(r2.remainingMs).toBeGreaterThan(0);
  });

  it("different channels have independent cooldowns", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-chans",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
      mention: { cooldownMs: 60_000 },
    });
    (bot.client as unknown as { _nick: string })._nick = "yokota";

    expect(bot.checkMention("#foo", "@yokota hi").kind).toBe("respond");
    expect(bot.checkMention("#bar", "@yokota hi").kind).toBe("respond");
    expect(bot.checkMention("#foo", "@yokota hi again").kind).toBe("cooldown");
  });

  it("cooldown disabled when cooldownMs is 0", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-no-cd",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
      mention: { cooldownMs: 0 },
    });
    (bot.client as unknown as { _nick: string })._nick = "yokota";

    expect(bot.checkMention("#foo", "@yokota a").kind).toBe("respond");
    expect(bot.checkMention("#foo", "@yokota b").kind).toBe("respond");
    expect(bot.checkMention("#foo", "@yokota c").kind).toBe("respond");
  });

  it("accepts a caller-supplied matcher (e.g. swarm-style start-anchored)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const startAnchored = (text: string, nick: string): string | null => {
      const m = /^@?(\S+?)[:,]?\s+(.*)$/s.exec(text);
      if (!m || m[1]!.toLowerCase() !== nick.toLowerCase()) return null;
      return m[2]!;
    };
    const bot = await FreeqBot.create({
      name: "mb-custom",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
      mention: { matcher: startAnchored },
    });
    (bot.client as unknown as { _nick: string })._nick = "yokota";

    // Matches: addressing at start
    expect(bot.checkMention("#foo", "yokota review github.com/x").kind).toBe(
      "respond",
    );
    // Doesn't match: mid-message address (custom matcher only allows start)
    expect(bot.checkMention("#bar", "hey @yokota help").kind).toBe("ignore");
  });

  it("reads the bot's current nick live (server-side rename picked up)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-live-nick",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
    });
    const client = bot.client as unknown as { _nick: string };

    client._nick = "yokota";
    expect(bot.checkMention("#foo", "@yokota hi").kind).toBe("respond");

    // Server renames us mid-session
    client._nick = "yokota2";
    expect(bot.checkMention("#bar", "@yokota hi").kind).toBe("ignore"); // old nick no longer addresses us
    expect(bot.checkMention("#bar", "@yokota2 hi").kind).toBe("respond"); // new nick does
  });

  it("returns ignore when the bot's nick is unset", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "mb-no-nick",
      ownerDid: "did:plc:owner",
      nick: "yokota",
      url: "wss://test/irc",
      root,
    });
    (bot.client as unknown as { _nick: string })._nick = "";
    expect(bot.checkMention("#foo", "@yokota hi").kind).toBe("ignore");
  });
});

describe("FreeqBot.setState", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("defaults state to 'active' and reflects in announce", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    expect(bot.state).toBe("active");

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const presence = ws.sent.find((l) => l.startsWith("PRESENCE "))!;
    expect(presence).toMatch(/state=active/);
    await bot.stop();
  });

  it("honors initialState option", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      initialState: "idle",
    });
    expect(bot.state).toBe("idle");
    await bot.stop();
  });

  it("setState() sends an immediate PRESENCE and updates state", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const before = ws.sent.length;
    bot.setState("executing", "reviewing PR #42");
    expect(bot.state).toBe("executing");

    const newLines = ws.sent.slice(before);
    expect(newLines.some((l) =>
      l.startsWith("PRESENCE ") && l.includes("state=executing") && l.includes("status=reviewing PR #42"),
    )).toBe(true);

    await bot.stop();
  });
});

describe("FreeqBot.stop", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("sends PRESENCE=offline + QUIT then disconnects", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const before = ws.sent.length;
    await bot.stop({ reason: "test", drainMs: 0 });

    const newLines = ws.sent.slice(before);
    expect(newLines.some((l) => l.startsWith("PRESENCE ") && l.includes("state=offline"))).toBe(true);
    expect(newLines.some((l) => l.startsWith("QUIT :test"))).toBe(true);
  });

  it("accepts a string reason (shorthand)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    await bot.stop("SIGINT");
    expect(ws.sent.some((l) => l === "QUIT :SIGINT")).toBe(true);
  });

  it("is idempotent", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    await bot.stop({ drainMs: 0 });
    const after = ws.sent.length;
    await bot.stop({ drainMs: 0 }); // second call should be a no-op
    expect(ws.sent.length).toBe(after);
  });
});

describe("FreeqBot event delegation", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("bot.on() forwards to client.on()", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    let receivedFromBot = false;
    let receivedFromClient = false;
    bot.on("ready", () => { receivedFromBot = true; });
    bot.client.on("ready", () => { receivedFromClient = true; });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    expect(receivedFromBot).toBe(true);
    expect(receivedFromClient).toBe(true);
    await bot.stop({ drainMs: 0 });
  });

  it("bot.off() removes the handler", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    let count = 0;
    const handler = (): void => { count++; };
    bot.on("ready", handler);
    bot.off("ready", handler);

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    expect(count).toBe(0);
    await bot.stop({ drainMs: 0 });
  });
});

describe("FreeqBot constructor option passthrough", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("auto-joins channels on connect (forwarded to SDK)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      channels: ["#mychan", "#other"],
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    expect(ws.sent.some((l) => l === "JOIN #mychan")).toBe(true);
    expect(ws.sent.some((l) => l === "JOIN #other")).toBe(true);
    await bot.stop({ drainMs: 0 });
  });

  it("includes initialStatus in the announce PRESENCE", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      initialState: "idle",
      initialStatus: "warming up",
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const presence = ws.sent.find((l) => l.startsWith("PRESENCE "))!;
    expect(presence).toMatch(/state=idle/);
    expect(presence).toMatch(/status=warming up/);
    await bot.stop({ drainMs: 0 });
  });

  it("uses the configured actorClass on AGENT REGISTER", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      actorClass: "external_agent",
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const reg = ws.sent.find((l) => l.startsWith("AGENT REGISTER "))!;
    expect(reg).toMatch(/class=external_agent/);
    await bot.stop({ drainMs: 0 });
  });

  it("honors heartbeatTtlS for HEARTBEAT messages", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      heartbeatTtlS: 120,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const hb = ws.sent.find((l) => l.startsWith("HEARTBEAT "))!;
    expect(hb).toMatch(/ttl=120/);
    await bot.stop({ drainMs: 0 });
  });
});

describe("FreeqBot announce ordering", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("sends MANIFEST after REGISTER and before PRESENCE", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      manifest: `[agent]\ndisplay_name = "x"\n[provenance]\norigin_type = "t"\ncreator_did = "did:plc:o"\nrevocation_authority = "did:plc:o"\n`,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const lines = ws.sent;
    const idxProv = lines.findIndex((l) => l.startsWith("PROVENANCE "));
    const idxReg = lines.findIndex((l) => l.startsWith("AGENT REGISTER "));
    const idxManifest = lines.findIndex((l) => l.startsWith("AGENT MANIFEST "));
    const idxPresence = lines.findIndex((l) => l.startsWith("PRESENCE "));

    expect(idxProv).toBeGreaterThanOrEqual(0);
    expect(idxReg).toBeGreaterThan(idxProv);
    expect(idxManifest).toBeGreaterThan(idxReg);
    expect(idxPresence).toBeGreaterThan(idxManifest);

    await bot.stop({ drainMs: 0 });
  });
});

describe("FreeqBot heartbeat", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(async () => {
    vi.useRealTimers();
    await rm(root, { recursive: true, force: true });
  });

  it("ticks heartbeats with current state at the configured interval", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      heartbeatMs: 1000,
      heartbeatTtlS: 5,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const before = ws.sent.filter((l) => l.startsWith("HEARTBEAT ")).length;
    vi.advanceTimersByTime(3500); // ~3 ticks
    await flushAsync();
    const afterFirst = ws.sent.filter((l) => l.startsWith("HEARTBEAT ")).length;
    expect(afterFirst - before).toBeGreaterThanOrEqual(3);

    // Change state. Subsequent heartbeats carry the new state.
    bot.setState("idle");
    // Capture the boundary AFTER setState + flush so any in-flight timer
    // callbacks scheduled before the state change don't race.
    await flushAsync();
    const boundary = ws.sent.length;

    vi.advanceTimersByTime(2500);
    await flushAsync();
    const newHeartbeats = ws.sent
      .slice(boundary)
      .filter((l) => l.startsWith("HEARTBEAT "));
    expect(newHeartbeats.length).toBeGreaterThan(0);
    for (const hb of newHeartbeats) {
      expect(hb).toMatch(/state=idle/);
    }

    await bot.stop({ drainMs: 0 });
  });

  it("stops the heartbeat loop on stop()", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      heartbeatMs: 1000,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    await bot.stop({ drainMs: 0 });
    const afterStop = ws.sent.filter((l) => l.startsWith("HEARTBEAT ")).length;
    vi.advanceTimersByTime(5000);
    await flushAsync();
    const later = ws.sent.filter((l) => l.startsWith("HEARTBEAT ")).length;
    // No new heartbeats after stop. (Some sends may fail because the socket
    // closed; either way we don't expect new HEARTBEAT lines.)
    expect(later).toBe(afterStop);
  });
});

describe("FreeqBot announce-on-reconnect", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("re-announces on every 'ready' (reconnect path)", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;

    const initialProvenanceCount = ws.sent.filter((l) => l.startsWith("PROVENANCE ")).length;
    expect(initialProvenanceCount).toBe(1);

    // Simulate another 'ready' (as if reconnect resumed). We can't easily
    // trigger transport.reconnect here, so emit a fresh 376 to re-fire ready.
    // First send a 001 (which the SDK uses as a marker for new registration).
    ws.recv(":srv 001 test-bot :Welcome (reconnect)");
    await flushAsync();
    ws.recv(":srv 376 test-bot :End of MOTD (reconnect)");
    await flushAsync();

    const provenanceAfter = ws.sent.filter((l) => l.startsWith("PROVENANCE ")).length;
    expect(provenanceAfter).toBeGreaterThan(initialProvenanceCount);

    await bot.stop({ drainMs: 0 });
  });
});

describe("session signing", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  /** Drive registration against a server that offers SASL and the signing
   *  cap, completing the crypto-SASL exchange with the bot's real did:key. */
  async function driveSigningReady(ws: MockWebSocket, nick: string): Promise<void> {
    await flushAsync();
    ws.recv(":srv CAP * LS :sasl message-tags freeq.at/msgsig");
    await flushAsync();
    ws.recv(":srv CAP * ACK :sasl message-tags freeq.at/msgsig");
    await flushAsync();
    const challenge = Buffer.from(JSON.stringify({ nonce: "n1" })).toString("base64url");
    ws.recv(`AUTHENTICATE ${challenge}`);
    await flushAsync();
    ws.recv(`:srv 903 ${nick} :SASL authentication successful`);
    await flushAsync();
    ws.recv(`:srv 001 ${nick} :Welcome`);
    await flushAsync();
    ws.recv(`:srv 376 ${nick} :End of MOTD`);
    await flushAsync();
  }

  it("a bot registers a session signing key like every other client", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveSigningReady(ws, "test-bot");
    await startPromise;

    // The MSGSIG mint is async off the 001 handler; give it a beat.
    for (let i = 0; i < 100 && !ws.sent.some((l) => l.startsWith("MSGSIG ")); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(
      ws.sent.some((l) => l.startsWith("MSGSIG ")),
      `no MSGSIG on the wire; sent: ${ws.sent.join(" | ")}`,
    ).toBe(true);
    await bot.stop({ drainMs: 0 });
  });
});

describe("session signing opt-out", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("autoMsgSig: false passes through — no session key is registered", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      autoMsgSig: false,
    });

    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await flushAsync();
    ws.recv(":srv CAP * LS :sasl message-tags freeq.at/msgsig");
    await flushAsync();
    ws.recv(":srv CAP * ACK :sasl message-tags freeq.at/msgsig");
    await flushAsync();
    const challenge = Buffer.from(JSON.stringify({ nonce: "n1" })).toString("base64url");
    ws.recv(`AUTHENTICATE ${challenge}`);
    await flushAsync();
    ws.recv(":srv 903 test-bot :SASL authentication successful");
    await flushAsync();
    ws.recv(":srv 001 test-bot :Welcome");
    await flushAsync();
    ws.recv(":srv 376 test-bot :End of MOTD");
    await flushAsync();
    await startPromise;

    // Symmetric wait to the opt-in test: give an (incorrect) async mint
    // every chance to appear before asserting it didn't.
    await new Promise((r) => setTimeout(r, 50));
    expect(
      ws.sent.some((l) => l.startsWith("MSGSIG ")),
      `unexpected MSGSIG; sent: ${ws.sent.join(" | ")}`,
    ).toBe(false);
    await bot.stop({ drainMs: 0 });
  });
});
