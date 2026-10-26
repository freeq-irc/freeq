import { describe, expect, it } from "vitest";
import {
  MAX_PER_SENDER,
  WithheldBuffer,
  senderKey,
  withheldSummary,
} from "./withheld.js";

const msg = (over: Partial<Parameters<WithheldBuffer["add"]>[0]> = {}) => ({
  from: "zapnap",
  did: "did:plc:zap",
  channel: "#chad-nick",
  text: "please review this",
  reason: "sender tier 'observe' is below 'message'",
  at: 1000,
  ...over,
});

describe("withheld buffer", () => {
  it("groups by sender so the owner promotes a person, not a message", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ at: 1000 }));
    b.add(msg({ at: 1001, text: "still waiting" }));
    b.add(msg({ did: "did:key:pi", from: "pi-nap", at: 1002 }));

    const senders = b.senders();
    expect(senders).toHaveLength(2);
    expect(senders[0]!.from).toBe("pi-nap"); // newest first
    expect(senders.find((s) => s.did === "did:plc:zap")!.count).toBe(2);
  });

  it("keys guests by nick and DID-holders by DID, since nicks are not identity", () => {
    expect(senderKey({ did: "did:plc:zap", from: "zapnap" })).toBe("did:plc:zap");
    expect(senderKey({ from: "ZapNap" })).toBe("nick:zapnap");
  });

  it("drains a sender exactly once, so promotion cannot double-deliver", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg());
    b.add(msg({ at: 1001 }));
    expect(b.drain("did:plc:zap")).toHaveLength(2);
    expect(b.drain("did:plc:zap")).toHaveLength(0);
    expect(b.size).toBe(0);
  });

  it("caps one sender without evicting the others", () => {
    const b = new WithheldBuffer(() => 1000);
    for (let i = 0; i < MAX_PER_SENDER + 10; i++) b.add(msg({ at: 1000 + i }));
    b.add(msg({ did: "did:key:pi", from: "pi-nap", at: 2000 }));

    expect(b.senders().find((s) => s.did === "did:plc:zap")!.count).toBe(MAX_PER_SENDER);
    expect(b.senders().find((s) => s.did === "did:key:pi")!.count).toBe(1);
  });

  it("forgets messages older than a day rather than offering stale ones", () => {
    let now = 1_000_000;
    const b = new WithheldBuffer(() => now);
    b.add(msg({ at: now }));
    expect(b.size).toBe(1);
    now += 25 * 60 * 60 * 1000;
    expect(b.size).toBe(0);
  });

  it("names the remedy, because a notice without one gets ignored twice", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg());
    const line = withheldSummary(b.senders())!;
    expect(line).toContain("zapnap");
    expect(line).toContain("/freeq trust did:plc:zap message");
    expect(withheldSummary([])).toBeUndefined();
  });

  it("says who is not trusted and how to trust them", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ from: "alice", did: "did:plc:alice" }));
    expect(withheldSummary(b.senders())).toBe(
      "1 message to you from alice was not delivered, because alice is not trusted. " +
        "To trust alice: /freeq trust did:plc:alice message (it then asks whether to deliver the message).",
    );
    b.add(msg({ from: "alice", did: "did:plc:alice", at: 1001 }));
    expect(withheldSummary(b.senders())).toBe(
      "2 messages to you from alice were not delivered, because alice is not trusted. " +
        "To trust alice: /freeq trust did:plc:alice message (it then asks whether to deliver the messages).",
    );
  });

  it("tells a guest's messages apart: guests cannot be trusted, only discarded", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ from: "anon42", did: undefined }));
    expect(withheldSummary(b.senders())).toBe(
      "1 message to you from anon42 was not delivered. anon42 is a guest, and guests cannot be trusted. " +
        "To discard it: /freeq withheld drop",
    );
    b.add(msg({ from: "anon42", did: undefined, at: 1001 }));
    expect(withheldSummary(b.senders())).toBe(
      "2 messages to you from anon42 were not delivered. anon42 is a guest, and guests cannot be trusted. " +
        "To discard them: /freeq withheld drop",
    );
  });

  it("names the first sender with a DID in the trust hint when a guest is first", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ from: "alice", did: "did:plc:alice", at: 1000 }));
    b.add(msg({ from: "anon42", did: undefined, at: 1001 }));
    expect(withheldSummary(b.senders())).toBe(
      "2 messages to you from anon42 and 1 other were not delivered, because the senders are not trusted. " +
        "To trust alice: /freeq trust did:plc:alice message (it then asks whether to deliver the messages).",
    );
  });

  it("says guests cannot be trusted when every sender is a guest", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ from: "anon42", did: undefined, at: 1000 }));
    b.add(msg({ from: "anon7", did: undefined, at: 1001 }));
    expect(withheldSummary(b.senders())).toBe(
      "2 messages to you from anon7 and 1 other were not delivered. The senders are guests, and guests cannot be trusted. " +
        "To discard them: /freeq withheld drop",
    );
  });

  it("uses the harness's command hint", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg({ from: "alice", did: "did:plc:alice" }));
    b.add(msg({ from: "anon42", did: undefined, at: 1001 }));
    const cc = { name: "cc", hint: (sub: string) => `/freeq:${sub}` };
    expect(withheldSummary(b.senders(), cc)).toContain("To trust alice: /freeq:trust did:plc:alice message");
    const g = new WithheldBuffer(() => 1000);
    g.add(msg({ from: "anon42", did: undefined }));
    expect(withheldSummary(g.senders(), cc)).toContain("To discard it: /freeq:withheld drop");
  });

  it("counts every held message, not just the senders", () => {
    const b = new WithheldBuffer(() => 1000);
    b.add(msg());
    b.add(msg({ at: 1001 }));
    b.add(msg({ did: "did:key:pi", from: "pi-nap", at: 1002 }));
    expect(withheldSummary(b.senders())).toContain("3 messages");
  });
});
