import { describe, expect, it } from "vitest";
import { SignInRefusedError } from "@freeq/bot-kit";
import { run, type RunBot } from "./run.js";

/** A bot whose start() does what `starts` says, and whose stop() settles
 *  `stopped` as bot-kit's does. */
class FakeBot implements RunBot {
  client = { nick: "fabro" };
  identity = { did: "did:key:zFabro" };
  stops: string[] = [];
  readyHandlers: Array<() => void> = [];
  retryHandlers: Array<(reason: string) => void> = [];
  #settle!: (reason: string) => void;
  readonly stopped = new Promise<string>((resolve) => (this.#settle = resolve));
  constructor(readonly starts: (bot: FakeBot) => Promise<"ready" | "deferred">) {}
  start(): Promise<"ready" | "deferred"> {
    return this.starts(this);
  }
  async stop(reason = ""): Promise<void> {
    this.stops.push(reason);
    this.#settle(reason);
  }
  on(event: "ready" | "authErrorRetry", handler: (...a: never[]) => void): unknown {
    if (event === "ready") this.readyHandlers.push(handler as () => void);
    else this.retryHandlers.push(handler as (reason: string) => void);
    return this;
  }
  emitReady(): void {
    for (const h of this.readyHandlers) h();
  }
  emitRetry(reason: string): void {
    for (const h of this.retryHandlers) h(reason);
  }
}

function harness(bot: FakeBot) {
  const logs: string[] = [];
  const exits: number[] = [];
  let opened = 0;
  let closed = 0;
  const signals = new Map<string, () => void>();
  const running = run({
    bot,
    startRelay: () => {
      opened++;
      return { close: () => void closed++ };
    },
    exit: (code) => void exits.push(code),
    log: (msg) => void logs.push(msg),
    onSignal: (signal, fn) => void signals.set(signal, fn),
  });
  return { running, logs, exits, signals, opened: () => opened, closed: () => closed };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const WORDS = "the agent records of did:plc:owner do not admit this agent";

describe("run", () => {
  it("a sign-in refused at start: logs the sentence, exits 0 once, and never opens the relay", async () => {
    const bot = new FakeBot(async () => {
      throw new SignInRefusedError(WORDS);
    });
    const h = harness(bot);
    await h.running;
    await tick();
    expect(h.logs).toEqual([`refused: ${WORDS} — shutting down`]);
    expect(h.exits).toEqual([0]);
    expect(h.opened()).toBe(0);
  });

  it("the same when the bot has already stopped itself, as bot-kit does before start() rejects", async () => {
    const bot = new FakeBot(async (b) => {
      void b.stop(WORDS);
      throw new SignInRefusedError(WORDS);
    });
    const h = harness(bot);
    await h.running;
    await tick();
    expect(h.logs).toEqual([`refused: ${WORDS} — shutting down`]);
    expect(h.exits).toEqual([0]);
    expect(h.opened()).toBe(0);
  });

  it("ready, then the bot stops itself: closes the relay once and exits 0 once", async () => {
    const bot = new FakeBot(async () => "ready");
    const h = harness(bot);
    await h.running;
    expect(h.opened()).toBe(1);
    await bot.stop("This device was signed out from another device.");
    await tick();
    expect(h.logs).toEqual([
      "connected as fabro (did:key:zFabro)",
      "refused: This device was signed out from another device. — shutting down",
    ]);
    expect(h.closed()).toBe(1);
    expect(h.exits).toEqual([0]);
  });

  it("deferred: no relay until the bot is in, then one", async () => {
    const bot = new FakeBot(async () => "deferred");
    const h = harness(bot);
    await h.running;
    expect(h.opened()).toBe(0);
    bot.emitReady();
    bot.emitReady();
    expect(h.opened()).toBe(1);
    expect(h.logs).toEqual(["connected as fabro (did:key:zFabro)"]);
  });

  it("a try-again: the sentence logged once until the bot is in, then again at a later one", async () => {
    const words = "Your identity could not be checked just now.";
    const bot = new FakeBot(async (b) => {
      b.emitRetry(words);
      return "deferred";
    });
    const h = harness(bot);
    await h.running;
    bot.emitRetry(words);
    bot.emitRetry(words);
    bot.emitReady();
    bot.emitRetry(words);
    expect(h.logs).toEqual([
      `the server could not check this bot just now: ${words}`,
      "connected as fabro (did:key:zFabro)",
      `the server could not check this bot just now: ${words}`,
    ]);
    expect(h.exits).toEqual([]);
  });

  it("start() fails for another reason: run rejects with it and never exits", async () => {
    const bot = new FakeBot(async () => {
      throw new Error("timeout waiting for ready (30000ms)");
    });
    const h = harness(bot);
    await expect(h.running).rejects.toThrow("timeout waiting for ready (30000ms)");
    expect(h.exits).toEqual([]);
  });

  it("a signal during start(): exits 0 once, and run resolves when start() then rejects", async () => {
    let reject!: (e: Error) => void;
    const bot = new FakeBot(() => new Promise((_, rej) => (reject = rej)));
    const h = harness(bot);
    await tick();
    h.signals.get("SIGTERM")!();
    await tick();
    reject(new Error("disconnected before ready"));
    await expect(h.running).resolves.toBeUndefined();
    await tick();
    expect(h.exits).toEqual([0]);
    expect(h.opened()).toBe(0);
    expect(h.logs).toEqual(["SIGTERM — shutting down"]);
  });
});
