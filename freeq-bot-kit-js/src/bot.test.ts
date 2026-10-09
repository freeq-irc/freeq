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

  it("hands its client the key lookup it is given", async () => {
    const { FreeqBot } = await import("./bot.js");
    const { KeyLookup } = await import("@freeq/sdk");
    const keyLookup = new KeyLookup({ fetch: async () => new Response(null, { status: 404 }), resolveDid: async () => { throw new Error("none"); } }, null, 60_000);
    const bot = await FreeqBot.create({
      name: "lookup-bot",
      ownerDid: "did:plc:owner",
      nick: "lookup-bot",
      url: "wss://test/irc",
      root,
      keyLookup,
      checkLines: false,
    });
    const opts = (bot.client as unknown as { opts: { keyLookup?: unknown; checkLines?: boolean } }).opts;
    expect(opts.keyLookup).toBe(keyLookup);
    expect(opts.checkLines).toBe(false);
  });

  it("makes its own key lookup, checking rulings only, when given none", async () => {
    const { FreeqBot } = await import("./bot.js");
    const { KeyLookup } = await import("@freeq/sdk");
    for (const [checkLines, expected] of [[undefined, false], [true, true]] as const) {
      const bot = await FreeqBot.create({
        name: "default-lookup-bot",
        ownerDid: "did:plc:owner",
        nick: "default-lookup-bot",
        url: "wss://test/irc",
        root,
        ...(checkLines === undefined ? {} : { checkLines }),
      });
      const opts = (bot.client as unknown as { opts: { keyLookup?: unknown; checkLines?: boolean } }).opts;
      expect(opts.keyLookup, String(checkLines)).toBeInstanceOf(KeyLookup);
      expect(opts.checkLines, String(checkLines)).toBe(expected);
    }
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

describe("FreeqBot message signing key", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  const CAPS = "message-tags server-time freeq.at/msgsig sasl";

  /** One connect of the bot named `test-bot` under `root`; the key its MSGSIG
   *  names, and the did:key's own public key, both base64url. */
  async function connectOnce(): Promise<{ sent: string; own: string }> {
    const { FreeqBot } = await import("./bot.js");
    const { decodeMultibaseEd25519 } = await import("@freeq/sdk");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(`:srv CAP * LS :${CAPS}`);
    await flushAsync();
    ws.recv(`:srv CAP * ACK :${CAPS}`);
    await flushAsync();
    ws.recv(":srv 903 test-bot :SASL authentication successful");
    await flushAsync();
    ws.recv(":srv 001 test-bot :Welcome");
    for (let i = 0; i < 200 && !ws.sent.some((l) => l.startsWith("MSGSIG ")); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    ws.recv(":srv 376 test-bot :End of MOTD");
    await startPromise;
    const line = ws.sent.find((l) => l.startsWith("MSGSIG "));
    await bot.stop();
    const own = Buffer.from(decodeMultibaseEd25519(bot.identity.didKey.publicKeyMultibase)).toString("base64url");
    return { sent: (line ?? "").slice("MSGSIG ".length).trim(), own };
  }

  it("presents the did:key's own public key on every connect", async () => {
    const first = await connectOnce();
    const second = await connectOnce();
    expect(first.sent).toBe(first.own);
    expect(second.sent).toBe(first.sent);
  });
});

describe("FreeqBot provenance result on stderr", () => {
  let root: string;
  let lines: string[];
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
    vi.useFakeTimers({ shouldAdvanceTime: true });
    lines = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    });
  });
  afterEach(async () => {
    vi.useRealTimers();
    await rm(root, { recursive: true, force: true });
  });

  const UNSIGNED =
    "Unsigned certificate: unverified until the owner adds this bot (did:key:zBot) under Settings → Agents";
  const RECORD = "Owner's agent record at://did:plc:owner/at.freeq.agentKey/3k names this bot";
  const provenanceLines = (): string[] => lines.filter((l) => /verified: /.test(l));

  async function started(opts: { logProvenance?: boolean } = {}): Promise<{
    bot: import("./bot.js").FreeqBot;
    ws: MockWebSocket;
  }> {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "test-bot",
      ownerDid: "did:plc:owner",
      nick: "test-bot",
      url: "wss://test/irc",
      root,
      ...opts,
    });
    const startPromise = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "test-bot");
    await startPromise;
    return { bot, ws };
  }

  async function reconnect(ws: MockWebSocket): Promise<void> {
    ws.recv(":srv 001 test-bot :Welcome (reconnect)");
    await flushAsync();
    ws.recv(":srv 376 test-bot :End of MOTD (reconnect)");
    await flushAsync();
  }

  it("logs only 'verified' when a verified reply follows the unverified one within the wait", async () => {
    const { bot, ws } = await started();
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(300);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    expect(provenanceLines()).toEqual([`provenance verified: ${RECORD}\n`]);
    await bot.stop({ drainMs: 0 });
  });

  it("logs 'unverified' with the reason after the wait when nothing verifies", async () => {
    const { bot, ws } = await started();
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(4000);
    expect(provenanceLines()).toEqual([]);

    await vi.advanceTimersByTimeAsync(2000);
    expect(provenanceLines()).toEqual([`provenance unverified: ${UNSIGNED}\n`]);
    await bot.stop({ drainMs: 0 });
  });

  it("logs a later 'Provenance unverified' from the server's re-check", async () => {
    const { bot, ws } = await started();
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    const gone = "Owner's agent record at://did:plc:owner/at.freeq.agentKey/3k no longer names this bot";
    ws.recv(`:srv NOTICE test-bot :Provenance unverified: ${gone}`);
    await flushAsync();

    expect(provenanceLines()).toEqual([
      `provenance verified: ${RECORD}\n`,
      `provenance unverified: ${gone}\n`,
    ]);
    await bot.stop({ drainMs: 0 });
  });

  it("does not log a reconnect that gets the same result again", async () => {
    const { bot, ws } = await started();
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    await reconnect(ws);
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(300);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    expect(provenanceLines()).toEqual([`provenance verified: ${RECORD}\n`]);
    await bot.stop({ drainMs: 0 });
  });

  it("lets the program read the current verdict with the server's full text", async () => {
    const { bot, ws } = await started();
    expect(bot.provenance).toBeNull();
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    await flushAsync();
    expect(bot.provenance).toEqual({
      verified: false,
      reason: UNSIGNED,
      text: `Provenance stored (unverified): ${UNSIGNED}`,
    });
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    expect(bot.provenance).toEqual({
      verified: true,
      reason: RECORD,
      text: `Provenance verified: ${RECORD}`,
    });
    await bot.stop({ drainMs: 0 });
  });

  it("tells the program when the verdict arrives and changes, not on a repeat", async () => {
    const { bot, ws } = await started();
    const seen: string[] = [];
    bot.onProvenance((v) => seen.push(`${v.verified}:${v.text}`));
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    await reconnect(ws);
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    ws.recv(`:srv NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    const gone = "Owner's agent record at://did:plc:owner/at.freeq.agentKey/3k no longer names this bot";
    ws.recv(`:srv NOTICE test-bot :Provenance unverified: ${gone}`);
    await flushAsync();

    expect(seen).toEqual([
      `true:Provenance verified: ${RECORD}`,
      `false:Provenance unverified: ${gone}`,
    ]);
    await bot.stop({ drainMs: 0 });
  });

  it("changes nothing on a user's NOTICE with the same text", async () => {
    const { bot, ws } = await started();
    const seen: unknown[] = [];
    bot.onProvenance((v) => seen.push(v));
    ws.recv(`:mallory!m@host NOTICE test-bot :Provenance verified: ${RECORD}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);
    expect(bot.provenance).toBeNull();
    expect(seen).toEqual([]);
    await bot.stop({ drainMs: 0 });
  });

  it("with logProvenance false writes nothing to stderr and still tells the program", async () => {
    const { bot, ws } = await started({ logProvenance: false });
    const seen: string[] = [];
    bot.onProvenance((v) => seen.push(`${v.verified}:${v.reason}`));
    ws.recv(`:srv NOTICE test-bot :Provenance stored (unverified): ${UNSIGNED}`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    expect(provenanceLines()).toEqual([]);
    expect(seen).toEqual([`false:${UNSIGNED}`]);
    await bot.stop({ drainMs: 0 });
  });

  it("ignores a 'Provenance' NOTICE sent by another user", async () => {
    const { bot, ws } = await started();
    ws.recv(`:mallory!m@host NOTICE test-bot :Provenance verified: trust me`);
    await flushAsync();
    await vi.advanceTimersByTimeAsync(6000);

    expect(provenanceLines()).toEqual([]);
    await bot.stop({ drainMs: 0 });
  });
});

describe("FreeqBot task rulings", () => {
  const ORIGIN = "https://server.test";
  const REFEREE = "did:web:referee.test";
  /** Seed 90's did:key: her openers check under the key her DID is. */
  const ALICE = "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD";
  const ROOM = "#tasks";

  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "freeq-bot-kit-bot-"));
  });
  afterEach(async () => {
    vi.unstubAllGlobals();
    await rm(root, { recursive: true, force: true });
  });

  const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

  async function keyOf(seed: number) {
    const { importDidKey } = await import("@freeq/sdk");
    const { deriveKid, publicKeyFromMultibase } = await import("./act.js");
    const key = await importDidKey(new Uint8Array(32).fill(seed));
    const pub = publicKeyFromMultibase(key.publicKeyMultibase);
    return { key, pub, kid: await deriveKid(pub) };
  }

  let ids = 0;
  /** Each event's canonical and signature by id, as the server's task
   *  history files them. */
  const canonicals = new Map<string, string>();
  const signatures = new Map<string, string>();
  /** A task event signed with `seed`'s key as `signer`: an opener when
   *  `task` is undefined, else `verb` on that task. */
  async function taskEvent(seed: number, signer: string, verb: string, task?: string, extra: Record<string, string> = {}) {
    const { actTags, format } = await import("@freeq/sdk");
    const { actCanonical, signActTags } = await import("./act.js");
    const id = `01K6Z${String(++ids).padStart(21, "0")}`;
    const tags = { ...actTags("handoff", verb, task, signer, {}), ...extra };
    canonicals.set(id, actCanonical(tags, ROOM, id)!);
    const sig = await signActTags(tags, ROOM, id, (await keyOf(seed)).key);
    signatures.set(id, sig!);
    const formatted = format("TAGMSG", [ROOM], { ...tags, "+freeq.at/eventid": id, "+freeq.at/sig": sig! });
    const split = formatted.indexOf(" ") + 1;
    return { id, wire: `${formatted.slice(0, split)}:sender!u@h ${formatted.slice(split)}` };
  }

  /** The connected server's task history and key routes, holding the key
   *  ALICE signs openers with, and the referee's own site, listing seed 91's
   *  key. */
  async function serve() {
    const referee = await keyOf(91);
    const alice = await keyOf(90);
    const aliceKey = { did: ALICE, kid: alice.kid, public_key: b64url(alice.pub), removed_at: null };
    vi.stubGlobal("fetch", vi.fn(async (input: string) => {
      const url = new URL(input);
      if (url.origin === "https://referee.test" && url.pathname === `/api/v1/signing-keys/${REFEREE}`) {
        return Response.json({ did: REFEREE, keys: [{ kid: referee.kid, public_key: b64url(referee.pub), removed_at: null }] });
      }
      if (url.origin === ORIGIN && url.pathname === "/api/v1/signing-keys") {
        const named = (url.searchParams.get("keys") ?? "").split(",");
        return Response.json({ keys: named.includes(`${ALICE}/${alice.kid}`) ? [aliceKey] : [] });
      }
      if (url.origin === ORIGIN && url.pathname === `/api/v1/signing-keys/${ALICE}/${alice.kid}`) {
        return Response.json(aliceKey);
      }
      const task = url.origin === ORIGIN && url.pathname.startsWith("/api/v1/actions/")
        ? decodeURIComponent(url.pathname.slice("/api/v1/actions/".length))
        : undefined;
      const canonical = task === undefined ? undefined : canonicals.get(task);
      if (canonical === undefined) return new Response("not found", { status: 404 });
      return Response.json({ events: [{ event_id: task, canonical, signature: signatures.get(task) }] });
    }));
  }

  it("passes a ruling that counts to its handlers, and never one that fails, through bot.on and bot.client.on alike", async () => {
    await serve();
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "ruling-bot",
      ownerDid: "did:plc:owner",
      nick: "ruling-bot",
      url: "wss://test/irc",
      serverOrigin: ORIGIN,
      root,
    });
    const seen: { id: string; ruling?: string }[] = [];
    bot.on("actEvent", (ev) => seen.push({ id: ev.eventId, ruling: ev.ruling }));
    // What the client itself sends up: the SDK throws a failing ruling out.
    const raw: { id: string; ruling?: string }[] = [];
    bot.client.on("actEvent", (ev) => raw.push({ id: ev.eventId, ruling: ev.ruling }));

    const started = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[0]!;
    await driveToReady(ws, "ruling-bot");
    await started;

    const home = { "+freeq.at/act-home": REFEREE };
    const first = await taskEvent(90, ALICE, "offer", undefined, home);
    const second = await taskEvent(90, ALICE, "offer", undefined, home);
    const counts = await taskEvent(91, REFEREE, "expire", first.id);
    // Seed 93's key is not on the referee's list.
    const fails = await taskEvent(93, REFEREE, "expire", second.id);
    for (const l of [first.wire, second.wire, counts.wire, fails.wire]) {
      ws.recv(l);
      await flushAsync();
    }
    for (let i = 0; i < 600 && raw.length < 3; i++) await new Promise((r) => setTimeout(r, 5));
    // Long enough for the failing ruling's check to have settled too.
    await new Promise((r) => setTimeout(r, 200));

    expect(seen.find((u) => u.id === counts.id)?.ruling).toBe("counts");
    expect(seen.map((u) => u.id)).toEqual([first.id, second.id, counts.id]);
    expect(raw.map((u) => u.id), "the client never hands it up").toEqual([first.id, second.id, counts.id]);
    await bot.stop({ drainMs: 0 });
  });

  it("learns a task's referee from the opener it saw, so a ruling needs no history read", async () => {
    await serve();
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "opener-bot",
      ownerDid: "did:plc:owner",
      nick: "opener-bot",
      url: "wss://test/irc",
      serverOrigin: ORIGIN,
      root,
    });
    const seen: { id: string; ruling?: string }[] = [];
    bot.on("actEvent", (ev) => seen.push({ id: ev.eventId, ruling: ev.ruling }));
    const started = bot.start();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    await driveToReady(ws, "opener-bot");
    await started;

    const opener = await taskEvent(90, ALICE, "offer", undefined, { "+freeq.at/act-home": REFEREE });
    ws.recv(opener.wire);
    await flushAsync();
    await new Promise((r) => setTimeout(r, 50));
    const ruling = await taskEvent(91, REFEREE, "expire", opener.id);
    ws.recv(ruling.wire);
    for (let i = 0; i < 600 && !seen.some((u) => u.id === ruling.id); i++) await new Promise((r) => setTimeout(r, 5));

    expect(seen.find((u) => u.id === ruling.id)?.ruling).toBe("counts");
    const asked = (globalThis.fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls.map((c) => String(c[0]));
    expect(asked.filter((u) => u.includes("/api/v1/actions/")), "no history read").toEqual([]);
    await bot.stop({ drainMs: 0 });
  });

  it("registers on(), once() and off() handlers on the client as they are", async () => {
    const { FreeqBot } = await import("./bot.js");
    const bot = await FreeqBot.create({
      name: "ruling-bot",
      ownerDid: "did:plc:owner",
      nick: "ruling-bot",
      url: "wss://test/irc",
      root,
    });
    const emit = (eventId: string, ruling?: string): void =>
      (bot.client as unknown as { emit: (e: string, p: unknown) => void }).emit("actEvent", { eventId, ruling });
    const once: string[] = [];
    const seen: string[] = [];
    const handler = (ev: { eventId: string }): void => { seen.push(ev.eventId); };
    bot.once("actEvent", (ev) => once.push(ev.eventId));
    bot.on("actEvent", handler);
    // Whatever the client emits reaches them: the SDK itself never emits a
    // failing ruling.
    emit("a", "fails");
    emit("b", "counts");
    bot.off("actEvent", handler);
    emit("c");
    expect(once).toEqual(["a"]);
    expect(seen).toEqual(["a", "b"]);
  });
});
