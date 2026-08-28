import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HandoffStore, hashBrief, describeHandoff, type ActEventLike } from "./handoff.js";

const ALICE = "did:key:zAlice";
const BOB = "did:key:zBob";
const MALLORY = "did:key:zMallory";

function ev(over: Partial<ActEventLike> = {}): ActEventLike {
  return {
    channel: "#work",
    from: "alice",
    did: ALICE,
    kind: "handoff",
    verb: "offer",
    eventId: "01OFFER0000000000000000000",
    taskId: "01OFFER0000000000000000000",
    fields: { act: "handoff", "act-to": BOB, "act-title": "Port the auth change" },
    sigTag: "ed25519:kid:sig",
    replayed: false,
    ...over,
  };
}

/** Offer → returns the task id. */
function offer(store: HandoffStore, over: Partial<ActEventLike> = {}): string {
  const e = ev(over);
  const r = store.apply(e);
  expect(r.ok, `offer should apply: ${r.ok ? "" : r.reason}`).toBe(true);
  return e.taskId;
}

function move(
  store: HandoffStore,
  verb: string,
  taskId: string,
  did: string,
  extra: Record<string, string> = {},
) {
  return store.apply(
    ev({
      verb,
      did,
      from: did.slice(-5),
      eventId: `01${verb.toUpperCase()}${Math.random().toString(36).slice(2, 8)}`,
      taskId,
      fields: { act: "handoff", "act-id": taskId, ...extra },
    }),
  );
}

let store: HandoffStore;
beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "handoff-test-"));
  store = new HandoffStore(join(dir, "h.json"));
});

describe("the happy path", () => {
  it("offer → accept → progress → complete", () => {
    const id = offer(store);
    expect(store.get(id)!.state).toBe("offered");

    expect(move(store, "accept", id, BOB).ok).toBe(true);
    expect(store.get(id)!.state).toBe("assigned");
    expect(store.get(id)!.assignee).toBe(BOB);

    expect(move(store, "progress", id, BOB, { "act-note": "halfway" }).ok).toBe(true);
    expect(store.get(id)!.state).toBe("assigned");

    expect(move(store, "complete", id, BOB).ok).toBe(true);
    expect(store.get(id)!.state).toBe("completed");
  });

  it("records an audit log of every applied move", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    move(store, "complete", id, BOB);
    const log = store.get(id)!.log;
    expect(log.map((l) => l.verb)).toEqual(["offer", "accept", "complete"]);
    expect(log.every((l) => !!l.by)).toBe(true);
  });

  it("decline is terminal", () => {
    const id = offer(store);
    expect(move(store, "decline", id, BOB).ok).toBe(true);
    expect(store.get(id)!.state).toBe("declined");
    expect(move(store, "accept", id, BOB).ok).toBe(false);
  });

  it("the offerer can cancel before acceptance", () => {
    const id = offer(store);
    expect(move(store, "cancel", id, ALICE).ok).toBe(true);
    expect(store.get(id)!.state).toBe("cancelled");
  });
});

describe("authorization — who may move a task", () => {
  it("a third party cannot accept work offered to someone else", () => {
    const id = offer(store);
    const r = move(store, "accept", id, MALLORY);
    expect(r.ok).toBe(false);
    expect(store.get(id)!.state).toBe("offered");
    expect(store.get(id)!.assignee).toBeUndefined();
  });

  it("the offerer cannot accept their own offer", () => {
    const id = offer(store);
    expect(move(store, "accept", id, ALICE).ok).toBe(false);
  });

  it("a non-assignee cannot complete the work", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    expect(move(store, "complete", id, MALLORY).ok).toBe(false);
    expect(move(store, "complete", id, ALICE).ok).toBe(false);
    expect(store.get(id)!.state).toBe("assigned");
  });

  it("the assignee cannot cancel (only the offerer can)", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    expect(move(store, "cancel", id, BOB).ok).toBe(false);
  });

  it("refuses events with no attributable DID", () => {
    const r = store.apply(ev({ did: undefined }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/DID/);
  });
});

describe("malformed and hostile input", () => {
  it("refuses an unknown kind", () => {
    const r = store.apply(ev({ kind: "bounty" }));
    expect(r.ok).toBe(false);
  });

  it("refuses a duplicate offer for the same id", () => {
    const id = offer(store);
    const r = store.apply(ev({ taskId: id }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/duplicate/);
  });

  it("refuses a move for a task it has never seen", () => {
    const r = move(store, "accept", "01UNKNOWN00000000000000000", BOB);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/unknown task/);
  });

  it("refuses moves on a finished task", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    move(store, "complete", id, BOB);
    for (const verb of ["accept", "progress", "complete", "cancel", "decline"]) {
      expect(move(store, verb, id, BOB).ok, `${verb} after completion`).toBe(false);
    }
  });

  it("refuses an unknown verb", () => {
    const id = offer(store);
    expect(move(store, "yolo", id, BOB).ok).toBe(false);
  });

  it("marks a task unsigned if any event lacked a signature", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    store.apply(
      ev({
        verb: "progress",
        did: BOB,
        taskId: id,
        eventId: "01PROG",
        fields: { act: "handoff", "act-id": id },
        sigTag: undefined,
      }),
    );
    expect(store.get(id)!.signed).toBe(false);
  });
});

describe("offline delivery", () => {
  it("marks offers that arrived by replay", () => {
    const id = offer(store, { replayed: true });
    expect(store.get(id)!.fromReplay).toBe(true);
  });

  it("lists work waiting for the recipient", () => {
    const id = offer(store, { replayed: true });
    const inbox = store.inboxFor(BOB);
    expect(inbox.map((r) => r.id)).toEqual([id]);
    expect(store.inboxFor(ALICE)).toEqual([]);
    expect(store.outboxFor(ALICE).map((r) => r.id)).toEqual([id]);
  });

  it("drops finished work from both inbox and outbox", () => {
    const id = offer(store);
    move(store, "accept", id, BOB);
    move(store, "complete", id, BOB);
    expect(store.inboxFor(BOB)).toEqual([]);
    expect(store.outboxFor(ALICE)).toEqual([]);
  });

  it("survives a restart", async () => {
    const dir = await mkdtemp(join(tmpdir(), "handoff-persist-"));
    const path = join(dir, "h.json");
    const a = new HandoffStore(path);
    const id = offer(a);
    move(a, "accept", id, BOB);
    await a.save();

    const b = new HandoffStore(path);
    await b.load();
    expect(b.get(id)!.state).toBe("assigned");
    expect(b.get(id)!.assignee).toBe(BOB);
    expect(b.inboxFor(BOB).length).toBe(1);
  });

  it("persists with owner-only permissions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "handoff-perm-"));
    const path = join(dir, "h.json");
    const s = new HandoffStore(path);
    offer(s);
    await s.save();
    const raw = await readFile(path, "utf8");
    expect(JSON.parse(raw)).toHaveLength(1);
  });

  it("tolerates a corrupt view rather than failing the session", async () => {
    const dir = await mkdtemp(join(tmpdir(), "handoff-corrupt-"));
    const path = join(dir, "h.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, "{ this is not json");
    const s = new HandoffStore(path);
    await expect(s.load()).resolves.toBeUndefined();
    expect(s.all()).toEqual([]);
  });
});

describe("context integrity", () => {
  it("hashes a brief deterministically", () => {
    expect(hashBrief("hello")).toBe(hashBrief("hello"));
    expect(hashBrief("hello")).not.toBe(hashBrief("hello "));
    expect(hashBrief("x")).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("keeps the signed context hash on the record", () => {
    const h = hashBrief("the brief");
    const id = offer(store, {
      fields: { act: "handoff", "act-to": BOB, "act-title": "T", "act-ctx-h": h },
    });
    expect(store.get(id)!.ctxHash).toBe(h);
  });
});

describe("describeHandoff", () => {
  it("orients the summary around the reader", () => {
    const id = offer(store);
    const rec = store.get(id)!;
    expect(describeHandoff(rec, ALICE)).toContain("→");
    expect(describeHandoff(rec, BOB)).toContain("←");
    expect(describeHandoff(rec, BOB)).toContain("offered");
  });
});

describe("routine wire traffic is not reported as failure", () => {
  it("treats a server confirm receipt as benign", () => {
    const id = offer(store);
    const r = store.apply(
      ev({ verb: "confirm", did: ALICE, taskId: id, fields: { act: "handoff", "act-id": id } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.benign).toBe(true);
    expect(store.get(id)!.state).toBe("offered"); // unchanged
  });

  it("treats a duplicate offer (echo or replay) as benign", () => {
    const id = offer(store);
    const r = store.apply(ev({ taskId: id }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.benign).toBe(true);
  });

  it("does NOT mark a genuinely illegal move as benign", () => {
    const id = offer(store);
    const r = move(store, "complete", id, MALLORY);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.benign).toBeFalsy();
  });
});
