import { describe, it, expect, vi } from "vitest";
import {
  AskRegistry,
  encodePayload,
  parseAskRequest,
  parseAskReply,
  newRequestId,
  MAX_ENCODED_PAYLOAD,
} from "./ask.js";

describe("AskRegistry — the exactly-one-response contract", () => {
  it("resolves on the first reply", async () => {
    const r = new AskRegistry();
    const p = r.create("req1", "peer");
    expect(r.deliver({ req: "req1", a: "42" }, "peer")).toBe(true);
    await expect(p).resolves.toEqual({ ok: true, answer: "42", from: "peer" });
    expect(r.size).toBe(0);
  });

  it("drops duplicate replies", async () => {
    const drops: string[] = [];
    const r = new AskRegistry((d) => drops.push(d));
    const p = r.create("req1", "peer");
    expect(r.deliver({ req: "req1", a: "first" }, "peer")).toBe(true);
    expect(r.deliver({ req: "req1", a: "second" }, "peer")).toBe(false);
    await expect(p).resolves.toMatchObject({ answer: "first" });
    expect(drops.join()).toMatch(/unknown\/expired|duplicate/);
  });

  it("rejects a reply from a peer we didn't ask (answer hijacking)", async () => {
    const drops: string[] = [];
    const r = new AskRegistry((d) => drops.push(d));
    const p = r.create("req1", "alice");
    expect(r.deliver({ req: "req1", a: "I'm not alice" }, "mallory")).toBe(false);
    expect(drops.join()).toMatch(/came from mallory, expected alice/);
    // Still outstanding — the real peer can still answer.
    expect(r.deliver({ req: "req1", a: "real" }, "alice")).toBe(true);
    await expect(p).resolves.toMatchObject({ answer: "real" });
  });

  it("is case-insensitive about the responder nick", async () => {
    const r = new AskRegistry();
    const p = r.create("req1", "Alice");
    expect(r.deliver({ req: "req1", a: "ok" }, "alice")).toBe(true);
    await expect(p).resolves.toMatchObject({ ok: true });
  });

  it("drops replies for unknown ids", () => {
    const drops: string[] = [];
    const r = new AskRegistry((d) => drops.push(d));
    expect(r.deliver({ req: "nope", a: "x" }, "peer")).toBe(false);
    expect(drops.join()).toMatch(/unknown\/expired/);
  });

  it("times out rather than hanging the caller's turn", async () => {
    vi.useFakeTimers();
    try {
      const r = new AskRegistry();
      const p = r.create("req1", "peer", 1_000);
      vi.advanceTimersByTime(1_100);
      await expect(p).resolves.toMatchObject({ ok: false });
      expect((await p).error).toMatch(/no reply from peer/);
      expect(r.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("ignores a reply that arrives after the timeout", async () => {
    vi.useFakeTimers();
    try {
      const r = new AskRegistry();
      const p = r.create("req1", "peer", 1_000);
      vi.advanceTimersByTime(1_100);
      await p;
      expect(r.deliver({ req: "req1", a: "late" }, "peer")).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("propagates a remote error as a failed result", async () => {
    const r = new AskRegistry();
    const p = r.create("req1", "peer");
    r.deliver({ req: "req1", err: "peer refused" }, "peer");
    await expect(p).resolves.toMatchObject({ ok: false, error: "peer refused" });
  });

  it("fails everything outstanding on disconnect", async () => {
    const r = new AskRegistry();
    const a = r.create("r1", "p");
    const b = r.create("r2", "p");
    r.cancelAll("disconnected");
    await expect(a).resolves.toMatchObject({ ok: false, error: "disconnected" });
    await expect(b).resolves.toMatchObject({ ok: false, error: "disconnected" });
    expect(r.size).toBe(0);
  });

  it("keeps concurrent asks independent", async () => {
    const r = new AskRegistry();
    const a = r.create("r1", "alice");
    const b = r.create("r2", "bob");
    r.deliver({ req: "r2", a: "from bob" }, "bob");
    r.deliver({ req: "r1", a: "from alice" }, "alice");
    await expect(a).resolves.toMatchObject({ answer: "from alice" });
    await expect(b).resolves.toMatchObject({ answer: "from bob" });
  });

  it("mints unique request ids", () => {
    const ids = new Set(Array.from({ length: 500 }, () => newRequestId()));
    expect(ids.size).toBe(500);
  });
});

describe("encodePayload", () => {
  it("leaves small payloads intact", () => {
    const { encoded, truncated } = encodePayload({ req: "r", a: "short" }, "a");
    expect(truncated).toBe(false);
    expect(JSON.parse(decodeURIComponent(encoded)).a).toBe("short");
  });

  it("truncates oversized text to fit the wire limit", () => {
    const { encoded, truncated } = encodePayload({ req: "r", a: "x".repeat(50_000) }, "a");
    expect(truncated).toBe(true);
    expect(encoded.length).toBeLessThanOrEqual(MAX_ENCODED_PAYLOAD);
    expect(JSON.parse(decodeURIComponent(encoded)).a).toMatch(/truncated/);
  });

  it("accounts for percent-encoding expansion, not raw length", () => {
    // Every char encodes to 9 bytes — raw-length budgeting would overshoot.
    const { encoded } = encodePayload({ req: "r", a: "😀".repeat(20_000) }, "a");
    expect(encoded.length).toBeLessThanOrEqual(MAX_ENCODED_PAYLOAD);
  });

  it("never emits tag-breaking characters", () => {
    const { encoded } = encodePayload({ req: "r", a: "a;b c\r\nd" }, "a");
    for (const bad of [";", " ", "\r", "\n"]) expect(encoded).not.toContain(bad);
  });
});

describe("payload parsing — hostile input", () => {
  it("rejects malformed requests", () => {
    for (const junk of [null, 42, "s", {}, { req: "" }, { req: "r" }, { req: "r", q: "  " }]) {
      expect(parseAskRequest(junk)).toBeUndefined();
    }
  });

  it("caps oversized fields", () => {
    const req = parseAskRequest({ req: "r".repeat(9999), q: "q".repeat(99999) });
    expect(req!.req.length).toBe(128);
    expect(req!.q.length).toBe(8000);
  });

  it("parses replies with either an answer or an error", () => {
    expect(parseAskReply({ req: "r", a: "x" })).toMatchObject({ a: "x" });
    expect(parseAskReply({ req: "r", err: "y" })).toMatchObject({ err: "y" });
    expect(parseAskReply({ req: "r" })).toMatchObject({ req: "r" });
    expect(parseAskReply({ a: "no req" })).toBeUndefined();
  });
});
