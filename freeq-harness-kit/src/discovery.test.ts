import { describe, it, expect } from "vitest";
import { buildHello, parseHello, helloTags, PI_HELLO, PI_PROTOCOL_VERSION } from "./discovery.js";

describe("hello round-trip", () => {
  it("survives the wire encoding", () => {
    const hello = buildHello(
      { project: "freeq", repo: "github.com/freeq-irc/freeq", branch: "main", model: "m" },
      "did:key:z6Mk",
    );
    const tags = helloTags(PI_HELLO, hello);
    expect(tags["+freeq.at/event"]).toBe(PI_HELLO);
    const decoded = JSON.parse(decodeURIComponent(tags["+freeq.at/payload"]));
    expect(parseHello(decoded)).toEqual(hello);
  });

  it("percent-encodes so tag delimiters can't break the wire", () => {
    const tags = helloTags(PI_HELLO, buildHello({ branch: "feat/a;b c" }, undefined));
    const payload = tags["+freeq.at/payload"];
    expect(payload).not.toContain(";");
    expect(payload).not.toContain(" ");
  });
});

describe("parseHello — hostile input", () => {
  it("rejects non-objects and bad versions", () => {
    for (const junk of [null, undefined, 42, "str", [], {}, { v: 0 }, { v: "1" }]) {
      expect(parseHello(junk)).toBeUndefined();
    }
  });

  it("drops unknown and non-string metadata fields", () => {
    const h = parseHello({
      v: 1,
      meta: { project: "freeq", cwd: "/Users/chad", evil: { a: 1 }, branch: 42 },
    });
    expect(h?.meta).toEqual({ project: "freeq" });
    expect(h?.meta).not.toHaveProperty("cwd");
  });

  it("caps field lengths so a peer can't flood the TUI", () => {
    const h = parseHello({ v: 1, meta: { branch: "x".repeat(5000) }, did: "d".repeat(5000) });
    expect(h?.meta.branch?.length).toBe(120);
    expect(h?.did?.length).toBe(200);
  });

  it("defaults a missing agent name rather than trusting it", () => {
    expect(parseHello({ v: 1, meta: {} })?.agent).toBe("unknown");
  });

  it("keeps the self-asserted did in the payload but marks the current version", () => {
    // The did here is informational only — connection.ts must never use it
    // for authorization (it resolves the DID server-side instead).
    const h = parseHello({ v: 1, meta: {}, did: "did:plc:liar" });
    expect(h?.did).toBe("did:plc:liar");
    expect(PI_PROTOCOL_VERSION).toBe(1);
  });
});
