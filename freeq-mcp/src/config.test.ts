import { describe, expect, it } from "vitest";
import { DEFAULT_SERVER, deriveWsUrl, loadConfig, splitChannels } from "./config.js";

describe("loadConfig", () => {
  it("works with an empty environment", () => {
    // The whole point: a client stanza with no `env` block at all works.
    const cfg = loadConfig({});
    expect(cfg.baseUrl).toBe(DEFAULT_SERVER);
    expect(cfg.wsUrl).toBe("wss://irc.freeq.at/irc");
    expect(cfg.channels).toEqual([]);
    expect(cfg.allowWrites).toBe(true);
    expect(cfg.ownerDid).toBeUndefined();
  });

  it("accepts a bare hostname and https-upgrades it", () => {
    const cfg = loadConfig({ FREEQ_SERVER: "irc.example.org" });
    expect(cfg.baseUrl).toBe("https://irc.example.org");
    expect(cfg.wsUrl).toBe("wss://irc.example.org/irc");
  });

  it("keeps ws (not wss) for a local http server", () => {
    // Local development is over plain http; deriving wss:// there would fail
    // to connect with a TLS error that looks nothing like the cause.
    const cfg = loadConfig({ FREEQ_SERVER: "http://127.0.0.1:6668" });
    expect(cfg.wsUrl).toBe("ws://127.0.0.1:6668/irc");
  });

  it("strips trailing slashes so paths don't double up", () => {
    expect(loadConfig({ FREEQ_SERVER: "https://x.test///" }).baseUrl).toBe("https://x.test");
  });

  it("honours an explicit websocket url", () => {
    const cfg = loadConfig({ FREEQ_SERVER: "https://a.test", FREEQ_WS_URL: "wss://b.test/sock" });
    expect(cfg.wsUrl).toBe("wss://b.test/sock");
  });

  it("treats FREEQ_READ_ONLY as a kill switch for writes", () => {
    expect(loadConfig({ FREEQ_READ_ONLY: "1" }).allowWrites).toBe(false);
    expect(loadConfig({ FREEQ_READ_ONLY: "true" }).allowWrites).toBe(false);
    expect(loadConfig({ FREEQ_READ_ONLY: "0" }).allowWrites).toBe(true);
    expect(loadConfig({ FREEQ_READ_ONLY: "" }).allowWrites).toBe(true);
  });

  it("clamps timeouts and row limits to sane ranges", () => {
    expect(loadConfig({ FREEQ_ASK_TIMEOUT_MS: "1" }).askTimeoutMs).toBe(1_000);
    expect(loadConfig({ FREEQ_ASK_TIMEOUT_MS: "99999999" }).askTimeoutMs).toBe(600_000);
    expect(loadConfig({ FREEQ_MAX_ROWS: "abc" }).maxRows).toBe(200);
    expect(loadConfig({ FREEQ_MAX_ROWS: "5000" }).maxRows).toBe(1_000);
  });
});

describe("splitChannels", () => {
  it("splits on commas and whitespace and adds missing hashes", () => {
    expect(splitChannels("general, #dev  ops")).toEqual(["#general", "#dev", "#ops"]);
  });

  it("is empty for undefined or blank", () => {
    expect(splitChannels(undefined)).toEqual([]);
    expect(splitChannels("  ")).toEqual([]);
  });

  it("leaves local channels alone", () => {
    expect(splitChannels("&local")).toEqual(["&local"]);
  });
});

describe("deriveWsUrl", () => {
  it("appends /irc without doubling slashes", () => {
    expect(deriveWsUrl("https://x.test/")).toBe("wss://x.test/irc");
    expect(deriveWsUrl("https://x.test")).toBe("wss://x.test/irc");
  });
});
