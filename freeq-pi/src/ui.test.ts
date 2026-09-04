import { describe, it, expect } from "vitest";
import {
  PEER_PALETTE,
  PEER_PALETTE_SIZE,
  footerLine,
  formatAge,
  offerCardLines,
  peerColor,
  peerColorIndex,
  rosterLines,
} from "./ui.js";

describe("footer", () => {
  it("says the important things in one glance", () => {
    const line = footerLine({ online: true, nick: "chad-bot-freeq", channels: 3, peers: 2, offersWaiting: 1, working: "handoff: fix parser" });
    expect(line).toBe("⬡ freeq · chad-bot-freeq · 3 ch · 2 peers · 1 offer ⏳ · ⚙ handoff: fix parser");
  });
  it("distinguishes offline from passive - they need different actions", () => {
    expect(footerLine({ online: false, channels: 0, peers: 0, offersWaiting: 0 })).toContain("offline");
    expect(footerLine({ online: false, passive: true, channels: 0, peers: 0, offersWaiting: 0 })).toContain("passive");
  });
  it("omits what is not happening", () => {
    const line = footerLine({ online: true, nick: "x", channels: 1, peers: 1, offersWaiting: 0 });
    expect(line).not.toContain("offer");
    expect(line).not.toContain("⚙");
    expect(line.endsWith("1 peer")).toBe(true); // singular, and last
  });
});

describe("offer card", () => {
  it("shows what, from whom, how long it has waited, and what to type", () => {
    const now = 1_700_000_000_000;
    const lines = offerCardLines(
      { taskId: "01M1PZGGZNXKM4MKFZJ22RQ1YG", title: "S2S probe round 1", from: "chad-bot-freeq", tier: "handoff", queuedAt: now - 90_000, brief: "Objective: find where…\nmore", now },
      60,
    );
    const text = lines.join("\n");
    expect(text).toContain("handoff offered");
    expect(text).toContain("S2S probe round 1");
    expect(text).toContain("from chad-bot-freeq (handoff) · 1m ago · 01M1PZGGZN");
    expect(text).toContain("Objective: find where…");
    expect(text).toContain("/freeq accept 01M1PZGGZN");
    expect(text).toContain("/freeq decline 01M1PZGGZN");
    // Box edges line up: every row the same width.
    const widths = new Set(lines.map((l) => [...l].length));
    expect(widths.size).toBe(1);
  });
  it("flags an overdue deadline", () => {
    const now = 1_700_000_000_000;
    const text = offerCardLines({ taskId: "T", title: "t", from: "a", tier: "handoff", queuedAt: now - 1000, deadline: now - 120_000, now }).join("\n");
    expect(text).toContain("2m overdue");
  });
});

describe("peer colours", () => {
  it("are stable per DID and spread across the palette", () => {
    expect(peerColorIndex("did:plc:a")).toBe(peerColorIndex("did:plc:a"));
    const seen = new Set(Array.from({ length: 200 }, (_, i) => peerColorIndex(`did:plc:${i}`)));
    expect(seen.size).toBe(PEER_PALETTE_SIZE);
    for (const i of seen) expect(i).toBeLessThan(PEER_PALETTE_SIZE);
  });
});

describe("roster", () => {
  it("is a table, newest first, showing what each peer is doing", () => {
    const now = 1_700_000_000_000;
    const lines = rosterLines(
      [
        { nick: "pi-nap", state: "active", project: "zerosum", model: "claude-opus-5", seen: now - 300_000, tier: "request" },
        { nick: "chad-bot-mdsnd", state: "executing", working: "cargo test", seen: now - 5_000 },
      ],
      now,
    );
    expect(lines[0]).toMatch(/^chad-bot-mdsnd\s+executing\s+⚙ cargo test\s+5s ago$/);
    expect(lines[1]).toMatch(/^pi-nap\s+active\s+in zerosum · claude-opus-5 · request\s+5m ago$/);
  });
  it("says why it is empty", () => {
    expect(rosterLines([])[0]).toMatch(/shared room/);
  });
});

describe("formatAge", () => {
  it("picks the unit a person would", () => {
    expect(formatAge(4_000)).toBe("4s");
    expect(formatAge(125_000)).toBe("2m");
    expect(formatAge(7_200_000)).toBe("2h");
    expect(formatAge(172_800_000)).toBe("2d");
  });
});

describe("footer honesty about channels", () => {
  it("counts confirmed joins and names refusals", () => {
    // The bug this encodes: #freeq-dev was policy-gated, the server said 477,
    // nothing listened, and the footer counted it as joined all session.
    const line = footerLine({ online: true, nick: "chad-bot-freeq", channels: 1, channelsRefused: 1, peers: 0, offers: 0 });
    expect(line).toContain("1 ch (1 refused)");
    const clean = footerLine({ online: true, nick: "chad-bot-freeq", channels: 2, peers: 0, offers: 0 });
    expect(clean).toContain("2 ch");
    expect(clean).not.toContain("refused");
  });
});

describe("footer names who is waiting", () => {
  it("shows withheld messages, because the alternative is looking like you ignored them", () => {
    const line = footerLine({ online: true, nick: "chad-bot-freeq", channels: 2, peers: 1, offers: 0, withheld: 3 });
    expect(line).toContain("3 withheld");
    const quiet = footerLine({ online: true, nick: "chad-bot-freeq", channels: 2, peers: 1, offers: 0 });
    expect(quiet).not.toContain("withheld");
  });
});

describe("peer colours", () => {
  it("is stable for a DID and drab for a stranger", () => {
    const a = peerColor("did:plc:k2n3e2vsihf3farequ44t5j7");
    expect(peerColor("did:plc:k2n3e2vsihf3farequ44t5j7")).toBe(a);
    expect(PEER_PALETTE).toContain(a);
    // No DID means no server-resolved identity, so no identity colour.
    expect(peerColor(undefined)).toBe("muted");
  });

  it("spreads DIDs across the palette rather than clustering", () => {
    const seen = new Set(
      Array.from({ length: 200 }, (_, i) => peerColor(`did:key:z6Mk${i}`)),
    );
    expect(seen.size).toBeGreaterThan(PEER_PALETTE.length / 2);
  });

  it("keys on the DID, not the nick, so a suffixed nick keeps its colour", () => {
    // pi auto-suffixes on nick collision; recolouring someone at exactly the
    // moment they become hard to identify would be the wrong trade.
    expect(peerColor("did:key:zSame")).toBe(peerColor("did:key:zSame"));
  });
});
