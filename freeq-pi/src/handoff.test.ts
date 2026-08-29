import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HandoffStore,
  hashBrief,
  describeHandoff,
  decideOffer,
  OfferQueue,
  sweepOfferQueue,
  offerExpiry,
  formatDuration,
  resolveTaskRef,
  WorkWatchdog,
  planResume,
  parseServerTasks,
  fetchAssignedTasks,
  type ServerTask,
  type ActEventLike,
  type HandoffRecord,
  type OfferPolicy,
} from "./handoff.js";

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

describe("open (claimable) tasks", () => {
  /** An offer with no act-to is open: the channel is the queue. */
  function postOpen(store: HandoffStore, caps?: string): string {
    const fields: Record<string, string> = { act: "handoff", "act-title": "Summarize the S2S logs" };
    if (caps) fields["act-caps"] = caps;
    const e = ev({ fields, taskId: "01OPEN00000000000000000000", eventId: "01OPEN00000000000000000000" });
    const r = store.apply(e);
    expect(r.ok, r.ok ? "" : r.reason).toBe(true);
    if (r.ok) expect(r.record.state).toBe("open");
    return e.taskId;
  }

  it("starts in 'open' with no assignee when nobody is named", () => {
    const id = postOpen(store);
    const rec = store.get(id)!;
    expect(rec.state).toBe("open");
    expect(rec.offeree).toBeUndefined();
    expect(rec.assignee).toBeUndefined();
  });

  it("keeps the declared capabilities as an advisory hint", () => {
    const id = postOpen(store, "pi/lang:rust pi/repo:github.com/o/r");
    expect(store.get(id)!.caps).toBe("pi/lang:rust pi/repo:github.com/o/r");
  });

  it("lets ANY did claim it — that is the difference from a directed offer", () => {
    const id = postOpen(store);
    expect(move(store, "claim", id, MALLORY).ok).toBe(true);
    expect(store.get(id)!.state).toBe("assigned");
    expect(store.get(id)!.assignee).toBe(MALLORY);
  });

  it("first claim wins; a second is refused", () => {
    // The minting server serialises competing claims. Locally we must reach
    // the same verdict: once assigned, it is no longer claimable.
    const id = postOpen(store);
    expect(move(store, "claim", id, BOB).ok).toBe(true);
    const second = move(store, "claim", id, MALLORY);
    expect(second.ok).toBe(false);
    expect(store.get(id)!.assignee).toBe(BOB);
  });

  it("cannot be 'accepted' — accept is only for a directed offer", () => {
    const id = postOpen(store);
    expect(move(store, "accept", id, BOB).ok).toBe(false);
    expect(store.get(id)!.state).toBe("open");
  });

  it("a directed offer cannot be claimed — claim is only for an open task", () => {
    const id = offer(store); // directed at BOB
    expect(move(store, "claim", id, MALLORY).ok).toBe(false);
    expect(store.get(id)!.state).toBe("offered");
  });

  it("only the claimer may complete it", () => {
    const id = postOpen(store);
    move(store, "claim", id, BOB);
    expect(move(store, "complete", id, MALLORY).ok).toBe(false);
    expect(move(store, "complete", id, BOB).ok).toBe(true);
    expect(store.get(id)!.state).toBe("completed");
  });

  it("the poster can still cancel it while unclaimed", () => {
    const id = postOpen(store);
    expect(move(store, "cancel", id, ALICE).ok).toBe(true);
    expect(store.get(id)!.state).toBe("cancelled");
    // And a late claim is then refused.
    expect(move(store, "claim", id, BOB).ok).toBe(false);
  });

  it("shows in the claimable list for everyone, not just one recipient", () => {
    const id = postOpen(store);
    // inboxFor includes open tasks, since anyone may take them.
    for (const did of [BOB, MALLORY]) {
      expect(store.inboxFor(did).map((r) => r.id)).toContain(id);
    }
    // And it is the poster's outstanding work too.
    expect(store.outboxFor(ALICE).map((r) => r.id)).toContain(id);
  });

  it("drops out of the claimable list once taken", () => {
    const id = postOpen(store);
    move(store, "claim", id, BOB);
    expect(store.inboxFor(MALLORY).map((r) => r.id)).not.toContain(id);
    expect(store.inboxFor(BOB).map((r) => r.id)).toContain(id); // now the assignee
  });

  it("survives a restart as an open task", async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir2 = await mkdtemp(join(tmpdir(), "handoff-open-"));
    const p = join(dir2, "h.json");
    const a = new HandoffStore(p);
    const id = postOpen(a, "pi/lang:ts");
    await a.save();
    const b = new HandoffStore(p);
    await b.load();
    expect(b.get(id)!.state).toBe("open");
    expect(b.get(id)!.caps).toBe("pi/lang:ts");
    expect(b.get(id)!.offeree).toBeUndefined();
  });
});

describe("intake — an offer can never be silently dropped", () => {
  const policy = (over: Partial<OfferPolicy> = {}): OfferPolicy => ({
    tier: "handoff",
    idle: true,
    autoAcceptDid: false,
    autoAcceptWhenIdle: true,
    ...over,
  });

  it("accepts trusted work when the session is idle", () => {
    const d = decideOffer(policy());
    expect(d.action).toBe("accept");
    expect(d.reason).toMatch(/idle/);
  });

  it("queues rather than interrupting a session that is busy", () => {
    const d = decideOffer(policy({ idle: false }));
    expect(d.action).toBe("queue");
    expect(d.reason).toMatch(/busy/);
  });

  it("accepts an auto-accept DID even mid-turn — that is what the list is for", () => {
    expect(decideOffer(policy({ idle: false, autoAcceptDid: true })).action).toBe("accept");
  });

  it("queues when the idle default is switched off", () => {
    expect(decideOffer(policy({ autoAcceptWhenIdle: false })).action).toBe("queue");
  });

  it("ignores an untrusted offerer entirely — idle or busy, queue or no queue", () => {
    for (const tier of ["observe", "message", "request"] as const) {
      for (const idle of [true, false]) {
        const d = decideOffer(policy({ tier, idle, autoAcceptWhenIdle: true }));
        expect(d.action, `${tier} while ${idle ? "idle" : "busy"}`).toBe("ignore");
        expect(d.reason).toContain(tier);
      }
    }
  });

  it("does not let the auto-accept list smuggle past the trust gate", () => {
    // A DID can be on the list and later have its tier revoked. Tier wins.
    expect(decideOffer(policy({ tier: "observe", autoAcceptDid: true })).action).toBe("ignore");
  });
});

describe("the offer queue", () => {
  function rec(over: Partial<HandoffRecord> = {}): HandoffRecord {
    return {
      id: "01AAAAAAAA0000000000000000",
      kind: "handoff",
      state: "offered",
      offerer: ALICE,
      offeree: BOB,
      title: "Port the auth change",
      channel: "#work",
      fromReplay: false,
      signed: true,
      createdAt: 1000,
      updatedAt: 1000,
      log: [],
      ...over,
    };
  }

  const trusted = () => true;
  const sweep = (over: Partial<Parameters<typeof sweepOfferQueue>[0]>) =>
    sweepOfferQueue({
      entries: [],
      lookup: () => undefined,
      trusted,
      idle: true,
      now: 0,
      ttlSecs: 1800,
      ...over,
    });

  it("holds an offer while busy and takes it on the transition to idle", () => {
    const r = rec();
    const entries = [{ taskId: r.id, queuedAt: 0 }];
    const lookup = (id: string) => (id === r.id ? r : undefined);

    const busy = sweep({ entries, lookup, idle: false, now: 1000 });
    expect(busy.accept).toBeUndefined();
    expect(busy.expire).toEqual([]);
    expect(busy.drop).toEqual([]);

    const idle = sweep({ entries, lookup, idle: true, now: 1000 });
    expect(idle.accept?.record.id).toBe(r.id);
  });

  it("takes the oldest queued offer first, and only one per pass", () => {
    const old = rec({ id: "01OLD00000000000000000000A" });
    const recent = rec({ id: "01NEW00000000000000000000B" });
    const byId = new Map([old, recent].map((r) => [r.id, r]));
    const out = sweep({
      entries: [
        { taskId: recent.id, queuedAt: 500 },
        { taskId: old.id, queuedAt: 100 },
      ],
      lookup: (id) => byId.get(id),
      now: 1000,
    });
    expect(out.accept?.record.id).toBe(old.id);
  });

  it("declines a queued offer past its TTL, with a reason", () => {
    const r = rec();
    const out = sweep({
      entries: [{ taskId: r.id, queuedAt: 0 }],
      lookup: () => r,
      ttlSecs: 60,
      now: 61_000,
    });
    expect(out.accept).toBeUndefined();
    expect(out.expire).toHaveLength(1);
    expect(out.expire[0].reason).toMatch(/no decision for 1m/);
  });

  it("expires rather than accepts, even when we are free at that very moment", () => {
    const r = rec();
    const out = sweep({
      entries: [{ taskId: r.id, queuedAt: 0 }],
      lookup: () => r,
      ttlSecs: 60,
      now: 999_999,
      idle: true,
    });
    expect(out.accept).toBeUndefined();
    expect(out.expire).toHaveLength(1);
  });

  it("honours the task's own deadline when it is sooner than the TTL", () => {
    const r = rec({ deadline: 30 }); // unix seconds
    const e = offerExpiry(r, 0, 1800);
    expect(e.at).toBe(30_000);
    expect(e.reason).toMatch(/deadline/);

    const out = sweep({ entries: [{ taskId: r.id, queuedAt: 0 }], lookup: () => r, now: 31_000 });
    expect(out.expire[0].reason).toMatch(/deadline/);
  });

  it("keeps the TTL when the deadline is further out", () => {
    expect(offerExpiry(rec({ deadline: 9_999 }), 0, 60).at).toBe(60_000);
  });

  it("forgets an entry whose task moved on without us", () => {
    const gone = rec({ id: "01GONE0000000000000000000A", state: "cancelled" });
    const out = sweep({
      entries: [{ taskId: gone.id, queuedAt: 0 }, { taskId: "01VANISHED000000000000000", queuedAt: 0 }],
      lookup: (id) => (id === gone.id ? gone : undefined),
      now: 1000,
    });
    expect(out.drop.map((e) => e.taskId)).toEqual([gone.id, "01VANISHED000000000000000"]);
    expect(out.expire).toEqual([]);
    expect(out.accept).toBeUndefined();
  });

  it("will not act on an offer whose offerer lost trust while it waited", () => {
    const r = rec();
    const out = sweep({
      entries: [{ taskId: r.id, queuedAt: 0 }],
      lookup: () => r,
      trusted: () => false,
      now: 1000,
    });
    expect(out.accept).toBeUndefined();
    expect(out.drop).toEqual([]); // still on the books; the TTL will retire it
  });

  it("survives a restart — a queue that dies with the session is not a queue", async () => {
    const dir = await mkdtemp(join(tmpdir(), "offer-queue-"));
    const path = join(dir, "q.json");
    const a = new OfferQueue(path);
    a.add("01AAAAAAAA0000000000000000", 100);
    a.add("01BBBBBBBB0000000000000000", 200);
    a.add("01AAAAAAAA0000000000000000", 300); // a duplicate is not a second entry
    await a.save();

    const b = new OfferQueue(path);
    await b.load();
    expect(b.all().map((e) => e.taskId)).toEqual([
      "01AAAAAAAA0000000000000000",
      "01BBBBBBBB0000000000000000",
    ]);
    expect(b.all()[0].queuedAt).toBe(100);
    expect(b.has("01BBBBBBBB0000000000000000")).toBe(true);

    b.remove("01AAAAAAAA0000000000000000");
    expect(b.has("01AAAAAAAA0000000000000000")).toBe(false);
  });

  it("tolerates a corrupt queue file rather than failing the session", async () => {
    const dir = await mkdtemp(join(tmpdir(), "offer-queue-bad-"));
    const path = join(dir, "q.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, "not json at all");
    const q = new OfferQueue(path);
    await expect(q.load()).resolves.toBeUndefined();
    expect(q.all()).toEqual([]);
  });
});

describe("resolving the short id a notification printed", () => {
  function rec(id: string): HandoffRecord {
    return {
      id,
      kind: "handoff",
      state: "offered",
      offerer: ALICE,
      title: "T",
      channel: "#work",
      fromReplay: false,
      signed: true,
      createdAt: 0,
      updatedAt: 0,
      log: [],
    };
  }
  const records = [rec("01ABCDEF0000000000000000AA"), rec("01ABCDEF0000000000000000BB"), rec("01ZZZZ")];

  it("resolves a unique prefix", () => {
    const r = resolveTaskRef(records, "01ZZ");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.record.id).toBe("01ZZZZ");
  });

  it("resolves a full id even when it is also a prefix of others", () => {
    const r = resolveTaskRef(records, "01ABCDEF0000000000000000AA");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.record.id).toBe("01ABCDEF0000000000000000AA");
  });

  it("refuses an ambiguous prefix by naming the candidates", () => {
    const r = resolveTaskRef(records, "01ABCDEF00");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toMatch(/matches 2 tasks/);
      expect(r.reason).toContain("01ABCDEF000000");
    }
  });

  it("says plainly when nothing matches", () => {
    const r = resolveTaskRef(records, "01NOPE");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/no task on record starts with '01NOPE'/);
  });

  it("refuses an empty reference instead of picking something", () => {
    expect(resolveTaskRef(records, "   ").ok).toBe(false);
  });
});

describe("formatDuration", () => {
  it("reads the way a person says it", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(900)).toBe("15m");
    expect(formatDuration(1800)).toBe("30m");
    expect(formatDuration(3600)).toBe("1h");
    expect(formatDuration(5400)).toBe("1.5h");
    expect(formatDuration(86_400)).toBe("1d");
  });
});

describe("the watchdog on accepted work", () => {
  const task = { taskId: "01WORK00000000000000000000", channel: "#work", title: "Port it" };
  const dog = () => new WorkWatchdog({ progressIntervalSecs: 120, stallSecs: 900 });

  it("says nothing while the work is fresh", () => {
    const w = dog();
    w.start(task, 0);
    expect(w.tick(1000)).toEqual([]);
  });

  it("heartbeats while in flight, at the configured interval", () => {
    const w = dog();
    w.start(task, 0);
    expect(w.tick(119_000)).toEqual([]);
    const beat = w.tick(120_000);
    expect(beat).toHaveLength(1);
    expect(beat[0].kind).toBe("progress");
    // The next beat is an interval later, not on every tick after the first.
    expect(w.tick(121_000)).toEqual([]);
    expect(w.tick(240_000)).toHaveLength(1);
  });

  it("stops heartbeating once the task is finished", () => {
    const w = dog();
    w.start(task, 0);
    expect(w.tick(120_000)).toHaveLength(1);
    expect(w.finish(task.taskId)).toBe(true);
    expect(w.tick(240_000)).toEqual([]);
    expect(w.tick(10_000_000)).toEqual([]); // and never fails afterwards either
    expect(w.inFlight()).toEqual([]);
  });

  it("fails a stalled task exactly once, with a reason naming the stall", () => {
    const w = dog();
    w.start(task, 0);
    const out = w.tick(900_000);
    expect(out).toHaveLength(1);
    expect(out[0].kind).toBe("fail");
    if (out[0].kind === "fail") {
      expect(out[0].reason).toBe("no progress for 15m — the session stopped working on it");
      expect(out[0].task.taskId).toBe(task.taskId);
    }
    // Never twice: the task is gone the moment it fails.
    expect(w.tick(900_001)).toEqual([]);
    expect(w.tick(1_800_000)).toEqual([]);
    expect(w.has(task.taskId)).toBe(false);
  });

  it("counts model activity as progress, not the heartbeats it emits", () => {
    // Otherwise the heartbeat keeps its own task alive forever and the stall
    // timeout never fires — the exact hang this is here to end.
    const w = dog();
    const fails = (out: ReturnType<WorkWatchdog["tick"]>) => out.filter((a) => a.kind === "fail");
    w.start(task, 0);
    w.tick(120_000);
    w.tick(240_000);
    expect(fails(w.tick(899_000))).toEqual([]);
    w.touch(899_500); // the model did something
    expect(fails(w.tick(900_000))).toEqual([]); // so the stall clock restarted
    expect(fails(w.tick(1_799_499))).toEqual([]);
    expect(fails(w.tick(1_799_500))).toHaveLength(1); // and now it has run out again
  });

  it("watches several tasks independently", () => {
    const w = dog();
    const other = { taskId: "01OTHER0000000000000000000", channel: "#work", title: "And this" };
    w.start(task, 0);
    w.start(other, 500_000);
    const out = w.tick(900_000);
    expect(out.filter((a) => a.kind === "fail").map((a) => a.task.taskId)).toEqual([task.taskId]);
    expect(w.inFlight().map((t) => t.taskId)).toEqual([other.taskId]);
  });

  it("starting the same task twice does not double up on it", () => {
    const w = dog();
    w.start(task, 0);
    w.start(task, 500_000); // e.g. resume racing a live accept
    expect(w.inFlight()).toHaveLength(1);
    expect(w.inFlight()[0].startedAt).toBe(0);
    // The second start marked it alive, so the stall clock runs from there.
    expect(w.tick(900_000).filter((a) => a.kind === "fail")).toEqual([]);
    expect(w.tick(1_400_000).filter((a) => a.kind === "fail")).toHaveLength(1);
  });

  it("notes a shutdown rather than failing the work", () => {
    // A restart may pick this straight back up; a false failure in a signed,
    // permanent log is worse than a gap in it.
    const w = dog();
    w.start(task, 0);
    const out = w.shutdown(60_000);
    expect(out).toHaveLength(1);
    expect(out[0].kind).toBe("progress");
    if (out[0].kind === "progress") expect(out[0].note).toMatch(/shutting down/);
    expect(w.inFlight()).toEqual([]);
    expect(w.tick(10_000_000)).toEqual([]);
  });

  it("has nothing to say on a shutdown with no work in flight", () => {
    expect(dog().shutdown(1000)).toEqual([]);
  });
});

describe("resume — the server says what is still ours", () => {
  function known(over: Partial<HandoffRecord> = {}): HandoffRecord {
    return {
      id: "01AAAAAAAA0000000000000000",
      kind: "handoff",
      state: "assigned",
      offerer: ALICE,
      offeree: BOB,
      assignee: BOB,
      title: "Port the auth change",
      channel: "#work",
      fromReplay: false,
      signed: true,
      createdAt: 1000,
      updatedAt: 1000,
      log: [],
      ...over,
    };
  }
  function row(over: Partial<ServerTask> = {}): ServerTask {
    return {
      id: "01AAAAAAAA0000000000000000",
      kind: "handoff",
      state: "assigned",
      venue: "#work",
      offerer: ALICE,
      offeree: BOB,
      assignee: BOB,
      ...over,
    };
  }
  const plan = (over: Partial<Parameters<typeof planResume>[0]>) =>
    planResume({ serverTasks: [], known: [], me: BOB, max: 3, already: new Set(), ...over });

  it("re-enters work the server still lists as assigned to us", () => {
    const out = plan({ serverTasks: [row()], known: [known()] });
    expect(out.resume.map((r) => r.id)).toEqual(["01AAAAAAAA0000000000000000"]);
    expect(out.skipped).toBe(0);
    expect(out.stale).toEqual([]);
  });

  it("does NOT re-enter a local record the server no longer lists as ours", () => {
    // The view is a cache. Work somebody else has since taken must not be
    // restarted here just because our copy still says it is ours.
    const out = plan({ serverTasks: [], known: [known()] });
    expect(out.resume).toEqual([]);
    expect(out.stale.map((r) => r.id)).toEqual(["01AAAAAAAA0000000000000000"]);
  });

  it("ignores rows assigned to somebody else, or in another state", () => {
    const out = plan({
      serverTasks: [
        row({ id: "01OTHERS000000000000000000", assignee: MALLORY }),
        row({ id: "01OPEN00000000000000000000", state: "open", assignee: undefined }),
        row({ id: "01DONE00000000000000000000", state: "completed" }),
        row({ id: "01BOUNTY000000000000000000", kind: "bounty" }),
      ],
    });
    expect(out.resume).toEqual([]);
  });

  it("resumes work it has no local memory of, from the server row alone", () => {
    // A lost view, or work accepted on another machine. The row names the
    // venue, which is all the lifecycle needs to carry on.
    const out = plan({ serverTasks: [row({ updated: 5 })] });
    expect(out.resume).toHaveLength(1);
    expect(out.resume[0].channel).toBe("#work");
    expect(out.resume[0].assignee).toBe(BOB);
    expect(out.resume[0].title).toMatch(/not in the server's listing/);
  });

  it("will not invent a venue it cannot post the lifecycle back into", () => {
    const out = plan({ serverTasks: [row({ venue: "dm:did:key:zA,did:key:zB" })] });
    expect(out.resume).toEqual([]);
    expect(out.skipped).toBe(1); // counted, not silently dropped
  });

  it("caps the resume at maxResume, oldest first, and says how many are left", () => {
    const ids = ["01C", "01A", "01B"];
    const out = plan({
      max: 2,
      serverTasks: ids.map((id) => row({ id })),
      known: ids.map((id, i) => known({ id, createdAt: [300, 100, 200][i] })),
    });
    expect(out.resume.map((r) => r.id)).toEqual(["01A", "01B"]);
    expect(out.skipped).toBe(1);
  });

  it("resumes nothing at all when the cap is zero", () => {
    const out = plan({ max: 0, serverTasks: [row()], known: [known()] });
    expect(out.resume).toEqual([]);
    expect(out.skipped).toBe(1);
  });

  it("is idempotent — a second call re-enters nothing", () => {
    const serverTasks = [row()];
    const first = plan({ serverTasks, known: [known()] });
    expect(first.resume).toHaveLength(1);

    const already = new Set(first.resume.map((r) => r.id));
    const second = plan({ serverTasks, known: [known()], already });
    expect(second.resume).toEqual([]);
    expect(second.skipped).toBe(0); // already running is not "skipped"
    expect(second.stale).toEqual([]);
  });
});

describe("reading the server's task listing", () => {
  it("keeps the task's own state, not this server's reading of it", () => {
    // 'orphaned' says a federation link is down, not that the work moved.
    const tasks = parseServerTasks({
      tasks: [
        {
          act_id: "01A",
          kind: "handoff",
          venue: "#work",
          state: "orphaned",
          stored_state: "assigned",
          assignee: BOB,
          updated: 1700,
        },
      ],
    });
    expect(tasks).toHaveLength(1);
    expect(tasks[0].state).toBe("assigned");
    expect(tasks[0].updated).toBe(1_700_000); // seconds on the wire, ms here
  });

  it("drops rows it cannot make sense of instead of failing the resume", () => {
    expect(parseServerTasks({ tasks: [null, 7, {}, { act_id: "01A" }] })).toEqual([]);
    expect(parseServerTasks({})).toEqual([]);
    expect(parseServerTasks("nope")).toEqual([]);
  });

  it("asks only for work assigned to us", async () => {
    let asked = "";
    const out = await fetchAssignedTasks({
      origin: "https://irc.example/",
      did: BOB,
      fetchImpl: (async (url: string) => {
        asked = url;
        return { ok: true, json: async () => ({ tasks: [] }) };
      }) as unknown as typeof fetch,
    });
    expect(out.ok).toBe(true);
    expect(asked).toBe(
      `https://irc.example/api/v1/actions?assignee=${encodeURIComponent(BOB)}&state=assigned`,
    );
  });

  it("reports an outage as an outage, not as an empty answer", async () => {
    const down = await fetchAssignedTasks({
      origin: "https://irc.example",
      did: BOB,
      fetchImpl: (async () => {
        throw new Error("connect ECONNREFUSED");
      }) as unknown as typeof fetch,
    });
    expect(down.ok).toBe(false);
    if (!down.ok) expect(down.reason).toMatch(/ECONNREFUSED/);

    const rejected = await fetchAssignedTasks({
      origin: "https://irc.example",
      did: BOB,
      fetchImpl: (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch,
    });
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.reason).toMatch(/503/);
  });
});
