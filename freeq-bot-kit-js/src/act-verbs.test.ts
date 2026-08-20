// What each verb helper puts on the wire.
//
// The signing itself is the SDK's and is covered by the shared fixtures; what
// these pin is the shape — the right verb, the actor named, the task named on
// a follow-up and never on an opener, and a companion line linked back.

import { describe, expect, it } from "vitest";
import { accept, cancel, claim, complete, decline, fail, offer, progress } from "./act-verbs.js";
import type { ActContext } from "./act-verbs.js";

interface Sent {
  target: string;
  tags: Record<string, string>;
  humanText: string;
  taskId?: string;
}

function ctxWith(sent: Sent[]): ActContext {
  return {
    did: "did:plc:bot",
    target: "#ops",
    client: {
      async sendAct(
        target: string,
        tags: Record<string, string>,
        opts: { humanText: string; taskId?: string },
      ) {
        sent.push({ target, tags, humanText: opts.humanText, taskId: opts.taskId });
        return "01JEVENT0000000000000000AA";
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  };
}

describe("offer", () => {
  it("names the actor and the title, and no task", async () => {
    const sent: Sent[] = [];
    await offer(ctxWith(sent), { title: "review the deploy" });
    const { tags } = sent[0];
    expect(tags["+freeq.at/act"]).toBe("handoff");
    expect(tags["+freeq.at/act-verb"]).toBe("offer");
    expect(tags["+freeq.at/from"]).toBe("did:plc:bot");
    expect(tags["+freeq.at/act-title"]).toBe("review the deploy");
    // An opener's own event id is the task's id, so it names no other task.
    expect(tags["+freeq.at/act-id"]).toBeUndefined();
    expect(sent[0].humanText).toContain("review the deploy");
  });

  it("is directed only when it names a recipient", async () => {
    const open: Sent[] = [];
    await offer(ctxWith(open), { title: "anyone?" });
    expect(open[0].tags["+freeq.at/act-to"]).toBeUndefined();

    const directed: Sent[] = [];
    await offer(ctxWith(directed), { title: "you", to: "did:plc:worker" });
    expect(directed[0].tags["+freeq.at/act-to"]).toBe("did:plc:worker");
  });

  it("carries the optional fields only when given", async () => {
    const bare: Sent[] = [];
    await offer(ctxWith(bare), { title: "t" });
    for (const k of ["act-caps", "act-deadline", "act-ctx", "act-ctx-h", "act-replaces"]) {
      expect(bare[0].tags[`+freeq.at/${k}`]).toBeUndefined();
    }
    const full: Sent[] = [];
    await offer(ctxWith(full), {
      title: "t",
      caps: "freeq.at/web-search",
      deadline: 1_788_000_000,
      ctx: "https://example/brief",
      ctxHash: "sha256:9f00",
    });
    expect(full[0].tags["+freeq.at/act-caps"]).toBe("freeq.at/web-search");
    expect(full[0].tags["+freeq.at/act-deadline"]).toBe("1788000000");
    expect(full[0].tags["+freeq.at/act-ctx"]).toBe("https://example/brief");
    expect(full[0].tags["+freeq.at/act-ctx-h"]).toBe("sha256:9f00");
  });

  /// The revival relation is an opener's, and it is the whole of what the
  /// re-offer says about the action it replaces.
  it("names the finished action it revives, when it revives one", async () => {
    const sent: Sent[] = [];
    await offer(ctxWith(sent), {
      title: "review the deploy, again",
      replaces: "01M16E7TC0ENDED00000000000",
    });
    expect(sent[0].tags["+freeq.at/act-replaces"]).toBe("01M16E7TC0ENDED00000000000");
    // Still an opener: its own event id is the new action's id.
    expect(sent[0].tags["+freeq.at/act-id"]).toBeUndefined();
  });
});

describe("the follow-ups", () => {
  const verbs = [
    ["accept", accept],
    ["decline", decline],
    ["claim", claim],
    ["progress", progress],
    ["complete", complete],
    ["fail", fail],
    ["cancel", cancel],
  ] as const;

  for (const [name, fn] of verbs) {
    it(`${name} names its verb, its actor and its task`, async () => {
      const sent: Sent[] = [];
      await fn(ctxWith(sent), "01JTASK00000000000000000BB");
      const { tags } = sent[0];
      expect(tags["+freeq.at/act-verb"]).toBe(name);
      expect(tags["+freeq.at/from"]).toBe("did:plc:bot");
      expect(tags["+freeq.at/act-id"]).toBe("01JTASK00000000000000000BB");
      expect(tags["+freeq.at/act"]).toBe("handoff");
      // The companion links to the task, not to the step.
      expect(sent[0].taskId).toBe("01JTASK00000000000000000BB");
      expect(sent[0].humanText).not.toBe("");
    });
  }

  it("carries a note when one is given, and none when not", async () => {
    const bare: Sent[] = [];
    await progress(ctxWith(bare), "T1");
    expect(bare[0].tags["+freeq.at/act-note"]).toBeUndefined();

    const noted: Sent[] = [];
    await progress(ctxWith(noted), "T1", { note: "halfway" });
    expect(noted[0].tags["+freeq.at/act-note"]).toBe("halfway");
    expect(noted[0].humanText).toContain("halfway");
  });

  it("lets the caller write the line people read", async () => {
    const sent: Sent[] = [];
    await complete(ctxWith(sent), "T1", { humanText: "shipped it ✅" });
    expect(sent[0].humanText).toBe("shipped it ✅");
  });
});

describe("what is not here", () => {
  it("has no expire helper: that move is the server's alone", async () => {
    const mod = await import("./act-verbs.js");
    expect(Object.keys(mod)).not.toContain("expire");
  });
});
