import { describe, it, expect } from "vitest";
import { generateDidKey } from "@freeq/sdk";
import { signActTags, deriveKid, publicKeyFromMultibase } from "@freeq/bot-kit";
import {
  verifyActEvent,
  venueFor,
  kidOf,
  sigTagOf,
  base64urlToBytes,
  type KeyFetcher,
} from "./verify.js";

const SELF = "did:key:zSelf";

/** Build a genuinely signed act event, the way the SDK would. */
async function signedEvent(over: { channel?: string; tags?: Record<string, string> } = {}) {
  const key = await generateDidKey();
  const channel = over.channel ?? "#work";
  const eventId = "01SIGNEDEVENT0000000000000";
  const tags: Record<string, string> = {
    "+freeq.at/act": "handoff",
    "+freeq.at/act-verb": "offer",
    "+freeq.at/act-title": "Port the auth change",
    "+freeq.at/from": key.did,
    ...over.tags,
  };
  const venue = channel.toLowerCase();
  const sigTag = await signActTags(tags, venue, eventId, key);
  const raw = publicKeyFromMultibase(key.publicKeyMultibase);
  const fetchKey: KeyFetcher = async () => raw;
  return {
    ev: { channel, did: key.did, eventId, tags, sigTag: sigTag ?? undefined },
    fetchKey,
    raw,
    key,
  };
}

describe("valid signatures", () => {
  it("verifies a real signed event", async () => {
    const { ev, fetchKey } = await signedEvent();
    const r = await verifyActEvent(ev, { fetchKey, selfDid: SELF });
    expect(r.outcome).toBe("valid");
  });

  it("looks the key up by the kid the signature names", async () => {
    const { ev, fetchKey, key } = await signedEvent();
    const asked: Array<[string, string]> = [];
    const spy: KeyFetcher = async (did, kid) => {
      asked.push([did, kid]);
      return fetchKey(did, kid);
    };
    await verifyActEvent(ev, { fetchKey: spy, selfDid: SELF });
    const expectedKid = await deriveKid(publicKeyFromMultibase(key.publicKeyMultibase));
    expect(asked).toEqual([[key.did, expectedKid]]);
  });
});

describe("invalid — real cryptographic failure, must be rejected", () => {
  it("rejects a tampered act field", async () => {
    // The whole point of signing: changing a covered tag must be detected.
    const { ev, fetchKey } = await signedEvent();
    ev.tags["+freeq.at/act-title"] = "Delete the production database";
    const r = await verifyActEvent(ev, { fetchKey, selfDid: SELF });
    expect(r.outcome).toBe("invalid");
  });

  it("rejects an ADDED act tag (open coverage)", async () => {
    const { ev, fetchKey } = await signedEvent();
    ev.tags["+freeq.at/act-deadline"] = "1788000000";
    expect((await verifyActEvent(ev, { fetchKey, selfDid: SELF })).outcome).toBe("invalid");
  });

  it("rejects a STRIPPED act tag", async () => {
    const { ev, fetchKey } = await signedEvent();
    delete ev.tags["+freeq.at/act-title"];
    expect((await verifyActEvent(ev, { fetchKey, selfDid: SELF })).outcome).toBe("invalid");
  });

  it("rejects a signature replayed into another venue", async () => {
    // Without the venue in the canonical, an offer signed in one room would
    // replay intact into another.
    const { ev, fetchKey } = await signedEvent({ channel: "#work" });
    const moved = { ...ev, channel: "#other" };
    expect((await verifyActEvent(moved, { fetchKey, selfDid: SELF })).outcome).toBe("invalid");
  });

  it("rejects a signature filed under a different event id", async () => {
    const { ev, fetchKey } = await signedEvent();
    expect(
      (await verifyActEvent({ ...ev, eventId: "01OTHERID0000000000000000" }, { fetchKey, selfDid: SELF }))
        .outcome,
    ).toBe("invalid");
  });

  it("rejects a key that does not match the named kid", async () => {
    const { ev } = await signedEvent();
    const other = await generateDidKey();
    const wrong: KeyFetcher = async () => publicKeyFromMultibase(other.publicKeyMultibase);
    expect((await verifyActEvent(ev, { fetchKey: wrong, selfDid: SELF })).outcome).toBe("invalid");
  });

  it("rejects a malformed signature tag", async () => {
    const { ev, fetchKey } = await signedEvent();
    const r = await verifyActEvent({ ...ev, sigTag: "garbage" }, { fetchKey, selfDid: SELF });
    expect(r.outcome).toBe("invalid");
  });
});

describe("unverifiable — an outage is not a forgery", () => {
  it("defers when the key store has no key on record", async () => {
    const { ev } = await signedEvent();
    const none: KeyFetcher = async () => undefined;
    const r = await verifyActEvent(ev, { fetchKey: none, selfDid: SELF });
    expect(r.outcome).toBe("unverifiable");
    expect(r.reason).toMatch(/no key on record/);
  });

  it("defers when the key lookup throws (origin unreachable)", async () => {
    // The RFC is explicit: a five-minute blip at a third server must not
    // permanently destroy a valid accept.
    const { ev } = await signedEvent();
    const down: KeyFetcher = async () => {
      throw new Error("ECONNREFUSED");
    };
    const r = await verifyActEvent(ev, { fetchKey: down, selfDid: SELF });
    expect(r.outcome).toBe("unverifiable");
    expect(r.reason).toMatch(/ECONNREFUSED/);
  });

  it("defers an unsigned event rather than condemning it", async () => {
    const { ev, fetchKey } = await signedEvent();
    const r = await verifyActEvent({ ...ev, sigTag: undefined, tags: {} }, { fetchKey, selfDid: SELF });
    expect(r.outcome).toBe("unverifiable");
  });

  it("defers when there is no sender DID to look a key up by", async () => {
    const { ev, fetchKey } = await signedEvent();
    const r = await verifyActEvent({ ...ev, did: undefined }, { fetchKey, selfDid: SELF });
    expect(r.outcome).toBe("unverifiable");
  });

  it("defers when the venue cannot be derived", async () => {
    const { ev, fetchKey } = await signedEvent();
    const r = await verifyActEvent(
      { ...ev, channel: "some-nick" },
      { fetchKey, selfDid: "" },
    );
    expect(r.outcome).toBe("unverifiable");
    expect(r.reason).toMatch(/venue/);
  });

  it("never returns 'invalid' merely because material was missing", async () => {
    const { ev } = await signedEvent();
    const cases = [
      { ...ev, sigTag: undefined, tags: {} },
      { ...ev, did: undefined },
    ];
    for (const c of cases) {
      const r = await verifyActEvent(c, { fetchKey: async () => undefined, selfDid: SELF });
      expect(r.outcome).not.toBe("invalid");
    }
  });
});

describe("venueFor", () => {
  it("lowercases a channel", () => {
    expect(venueFor("#Work", SELF)).toBe("#work");
  });

  it("sorts DM participants so both ends agree", () => {
    const a = venueFor("did:key:zB", "did:key:zA");
    const b = venueFor("did:key:zA", "did:key:zB");
    expect(a).toBe("dm:did:key:zA,did:key:zB");
    expect(a).toBe(b);
  });

  it("falls back to the sender DID for a nick target", () => {
    expect(venueFor("bob", "did:key:zA", "did:key:zBob")).toBe("dm:did:key:zA,did:key:zBob");
  });

  it("gives up rather than guessing when it cannot tell", () => {
    expect(venueFor("bob", "did:key:zA")).toBeUndefined();
    expect(venueFor("did:key:zB", "")).toBeUndefined();
  });
});

describe("tag and kid helpers", () => {
  it("finds the sig tag with or without the client prefix", () => {
    expect(sigTagOf({ channel: "#c", eventId: "1", tags: { "+freeq.at/sig": "x" } })).toBe("x");
    expect(sigTagOf({ channel: "#c", eventId: "1", tags: { "freeq.at/sig": "y" } })).toBe("y");
    expect(sigTagOf({ channel: "#c", eventId: "1", tags: {} })).toBeUndefined();
  });

  it("extracts the kid", () => {
    expect(kidOf("ed25519:abc123:sigsig")).toBe("abc123");
    expect(kidOf("nope")).toBeUndefined();
    expect(kidOf("ed25519::sig")).toBeUndefined();
  });

  it("decodes base64url without padding", () => {
    expect(base64urlToBytes("AAEC")).toEqual(new Uint8Array([0, 1, 2]));
    expect(base64urlToBytes("_w").length).toBe(1);
  });
});
