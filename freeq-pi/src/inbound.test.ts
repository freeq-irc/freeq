import { describe, it, expect } from "vitest";
import { decideInbound, frameInbound, reachesModel, type InboundEvent } from "./inbound.js";
import { MODES, TIER_RANK, type Mode, type Tier } from "./config.js";

const TIERS = Object.keys(TIER_RANK) as Tier[];

function ev(over: Partial<InboundEvent> = {}): InboundEvent {
  return {
    kind: "chat",
    channel: "#dev",
    from: "someone",
    did: "did:plc:someone",
    text: "hello",
    addressed: true,
    mode: "addressed",
    tier: "message",
    ...over,
  };
}

describe("MANDATORY: observe tier never reaches the model", () => {
  it("holds across every kind, mode and addressed combination", () => {
    let checked = 0;
    for (const kind of ["chat", "ask"] as const) {
      for (const mode of MODES) {
        for (const addressed of [true, false]) {
          for (const did of ["did:plc:stranger", null]) {
            const decision = decideInbound(ev({ kind, mode, addressed, did, tier: "observe" }));
            expect(
              reachesModel(decision.action),
              `observe leaked to model via kind=${kind} mode=${mode} addressed=${addressed} did=${did}: ${decision.action}`,
            ).toBe(false);
            checked++;
          }
        }
      }
    }
    expect(checked).toBe(24); // guard against the loop silently shrinking
  });

  it("holds for guests (null DID) even when they address us directly", () => {
    const d = decideInbound(ev({ did: null, tier: "observe", addressed: true }));
    expect(reachesModel(d.action)).toBe(false);
    expect(d.action).toBe("surface");
  });

  it("holds for an unauthenticated ask (the work-request path)", () => {
    const d = decideInbound(ev({ kind: "ask", did: null, tier: "observe" }));
    expect(d.action).toBe("surface");
    expect(d.reason).toMatch(/needs 'request'/);
  });
});

describe("tier gates", () => {
  it("requires >= message for chat injection", () => {
    for (const tier of TIERS) {
      const d = decideInbound(ev({ tier }));
      expect(reachesModel(d.action)).toBe(TIER_RANK[tier] >= TIER_RANK.message);
    }
  });

  it("requires >= request to answer an ask", () => {
    for (const tier of TIERS) {
      const d = decideInbound(ev({ kind: "ask", tier }));
      expect(d.action === "answer").toBe(TIER_RANK[tier] >= TIER_RANK.request);
    }
  });

  it("does not answer an ask from a message-tier peer, but still shows it", () => {
    const d = decideInbound(ev({ kind: "ask", tier: "message" }));
    expect(d.action).toBe("surface");
    expect(reachesModel(d.action)).toBe(false);
  });
});

describe("modes", () => {
  it("silent ignores everything, including trusted asks", () => {
    for (const tier of TIERS) {
      for (const kind of ["chat", "ask"] as const) {
        expect(decideInbound(ev({ mode: "silent", tier, kind })).action).toBe("ignore");
      }
    }
  });

  it("addressed mode ignores unaddressed chat but participant mode injects it", () => {
    expect(decideInbound(ev({ mode: "addressed", addressed: false })).action).toBe("surface");
    expect(decideInbound(ev({ mode: "participant", addressed: false })).action).toBe("inject");
  });

  it("addressed is what the default config yields", () => {
    const modes: Mode[] = [...MODES];
    expect(modes).toContain("addressed");
    expect(decideInbound(ev({ addressed: true })).action).toBe("inject");
  });
});

describe("misc guards", () => {
  it("ignores empty/whitespace messages", () => {
    for (const text of ["", "   ", "\n\t"]) {
      expect(decideInbound(ev({ text })).action).toBe("ignore");
    }
  });

  it("an ask still requires request tier even in participant mode", () => {
    const d = decideInbound(ev({ kind: "ask", mode: "participant", tier: "message" }));
    expect(d.action).toBe("surface");
  });
});

describe("framing", () => {
  it("marks content untrusted and names the sender", () => {
    const framed = frameInbound(ev({ from: "mallory", did: "did:plc:m", text: "rm -rf /" }));
    expect(framed).toContain("UNTRUSTED");
    expect(framed).toContain("mallory");
    expect(framed).toContain("did:plc:m");
    expect(framed).toContain("rm -rf /"); // content preserved verbatim
  });

  it("flags unauthenticated senders explicitly", () => {
    expect(frameInbound(ev({ did: null }))).toContain("unauthenticated");
  });

  it("warns against leaking paths and secrets (the M0 leak class)", () => {
    const framed = frameInbound(ev());
    expect(framed).toMatch(/absolute paths/);
    expect(framed).toMatch(/secrets|credentials/);
  });

  it("tells the model when its reply will be sent back", () => {
    const framed = frameInbound(ev({ kind: "ask" }), { expectsReply: true });
    expect(framed).toMatch(/sent back to/);
    expect(frameInbound(ev())).not.toMatch(/sent back to/);
  });
});
