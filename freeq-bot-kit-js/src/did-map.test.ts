import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, writeFile, unlink, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDidMap, type DidMapMutable, type DidMapReadOnly } from "./did-map.js";

interface Entry {
  did: string;
  tier?: "basic" | "sensitive";
  label?: string;
}

async function tmp(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "did-map-test-"));
}

/** Force a poll-detectable mtime change by setting mtime well into the future. */
async function bumpMtime(path: string): Promise<void> {
  const { utimes } = await import("node:fs/promises");
  const now = new Date();
  // 2s ahead so mtimeMs definitely differs from any prior read
  await utimes(path, now, new Date(now.getTime() + 2000));
}

// Helper: wait until predicate is true, polling at 10ms intervals up to `maxMs`.
async function waitFor<T>(check: () => T | undefined | null | false, maxMs = 1000): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    const r = check();
    if (r) return r;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`waitFor: timeout after ${maxMs}ms`);
}

// ── source: static array ────────────────────────────────────────────────

describe("createDidMap: static array source", () => {
  it("loads the initial entries", async () => {
    const m = await createDidMap<Entry>({
      load: [{ did: "did:plc:a" }, { did: "did:plc:b", tier: "sensitive" }],
    });
    expect(m.has("did:plc:a")).toBe(true);
    expect(m.has("did:plc:c")).toBe(false);
    expect(m.get("did:plc:b")?.tier).toBe("sensitive");
    expect(m.list().length).toBe(2);
    m.close();
  });

  it("returns a copy from list() — mutating it doesn't affect internal state", async () => {
    const m = await createDidMap<Entry>({ load: [{ did: "did:plc:a" }] });
    const l = m.list();
    l.push({ did: "did:plc:b" });
    expect(m.has("did:plc:b")).toBe(false);
    m.close();
  });

  it("reload() on a static array is a no-op (returns same entries)", async () => {
    const arr = [{ did: "did:plc:a" }];
    const m = await createDidMap<Entry>({ load: arr });
    arr.push({ did: "did:plc:b" }); // mutating the source array
    await m.reload();
    // The array was captured by ref but it's the SAME reference each time.
    // This is documented behavior: mutate-after-create may or may not be
    // observed; tests assert only on observable invariants.
    expect(m.has("did:plc:a")).toBe(true);
    m.close();
  });
});

// ── source: function ────────────────────────────────────────────────────

describe("createDidMap: function source", () => {
  it("loads from the loader function", async () => {
    const m = await createDidMap<Entry>({
      load: async () => [{ did: "did:plc:fn1" }, { did: "did:plc:fn2" }],
    });
    expect(m.list().length).toBe(2);
    expect(m.has("did:plc:fn1")).toBe(true);
    m.close();
  });

  it("reload() re-invokes the loader", async () => {
    let counter = 0;
    const m = await createDidMap<Entry>({
      load: async () => {
        counter++;
        return [{ did: `did:plc:call${counter}` }];
      },
    });
    expect(m.has("did:plc:call1")).toBe(true);
    await m.reload();
    expect(m.has("did:plc:call1")).toBe(false);
    expect(m.has("did:plc:call2")).toBe(true);
    m.close();
  });

  it("propagates loader errors on initial load", async () => {
    await expect(
      createDidMap<Entry>({
        load: async () => {
          throw new Error("boom on init");
        },
      }),
    ).rejects.toThrow("boom on init");
  });

  it("propagates loader errors on reload", async () => {
    let first = true;
    const m = await createDidMap<Entry>({
      load: async () => {
        if (first) {
          first = false;
          return [{ did: "did:plc:a" }];
        }
        throw new Error("reload failed");
      },
    });
    await expect(m.reload()).rejects.toThrow("reload failed");
    m.close();
  });

  it("does not poll a function source (no setInterval)", async () => {
    // Spy on setInterval; if the impl polls function sources we'd see a call.
    const spy = vi.spyOn(global, "setInterval");
    const m = await createDidMap<Entry>({ load: async () => [] });
    expect(spy).not.toHaveBeenCalled();
    m.close();
    spy.mockRestore();
  });
});

// ── source: file (initial load) ────────────────────────────────────────

describe("createDidMap: file source (initial load)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmp();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("loads + parses the file", async () => {
    const path = join(dir, "list.json");
    await writeFile(
      path,
      JSON.stringify({ entries: [{ did: "did:plc:a", tier: "basic" }] }),
    );
    const m = await createDidMap<Entry>({
      load: { path, parse: (raw) => (JSON.parse(raw) as { entries: Entry[] }).entries },
    });
    expect(m.has("did:plc:a")).toBe(true);
    expect(m.get("did:plc:a")?.tier).toBe("basic");
    m.close();
  });

  it("treats ENOENT as empty (file just hasn't been created yet)", async () => {
    const m = await createDidMap<Entry>({
      load: { path: join(dir, "missing.json"), parse: JSON.parse },
    });
    expect(m.list()).toEqual([]);
    m.close();
  });

  it("propagates parse errors on initial load (refuses to start with unknown state)", async () => {
    const path = join(dir, "bad.json");
    await writeFile(path, "not valid json");
    await expect(
      createDidMap<Entry>({
        load: { path, parse: (raw) => JSON.parse(raw) as Entry[] },
      }),
    ).rejects.toThrow();
  });
});

// ── source: file (mtime-poll reload) ───────────────────────────────────

describe("createDidMap: file source (mtime-poll reload)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmp();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("reloads when the file's mtime changes", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:a" }]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
    });
    expect(m.has("did:plc:a")).toBe(true);

    await writeFile(path, JSON.stringify([{ did: "did:plc:b" }]));
    await bumpMtime(path);

    await waitFor(() => m.has("did:plc:b") && !m.has("did:plc:a"), 2000);
    m.close();
  });

  it("fires onChange after a successful reload", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:a" }]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
    });
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));

    await writeFile(path, JSON.stringify([{ did: "did:plc:b" }]));
    await bumpMtime(path);

    await waitFor(() => fires.length > 0, 2000);
    expect(fires[0]?.[0]?.did).toBe("did:plc:b");
    m.close();
  });

  it("treats file-deleted as empty (swap to empty list, fires onChange once)", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:a" }]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
    });
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));

    await unlink(path);
    await waitFor(() => m.list().length === 0, 2000);

    expect(fires.length).toBe(1);
    expect(fires[0]).toEqual([]);
    m.close();
  });

  it("retains previous state on parse error during reload (logs warning)", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:good" }]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await writeFile(path, "garbage }{}{ not json");
      await bumpMtime(path);

      // Wait long enough for at least one poll to attempt the reload.
      await new Promise((r) => setTimeout(r, 150));

      // Previous state retained
      expect(m.has("did:plc:good")).toBe(true);
      // Warning was emitted
      const calls = warn.mock.calls.flat().join(" ");
      expect(calls).toContain("reload failed");
      expect(calls).toContain("Retaining previous state");
    } finally {
      warn.mockRestore();
      m.close();
    }
  });

  it("close() stops the poll loop", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:a" }]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
    });
    m.close();

    // Mutate the file: a still-polling map would pick this up; a closed one won't.
    await writeFile(path, JSON.stringify([{ did: "did:plc:b" }]));
    await bumpMtime(path);
    await new Promise((r) => setTimeout(r, 150));
    expect(m.has("did:plc:a")).toBe(true);
    expect(m.has("did:plc:b")).toBe(false);
  });
});

// ── mutation (save-gated) ───────────────────────────────────────────────

describe("createDidMap: mutation (save provided)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmp();
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("set() upserts in-memory and awaits save before mutating state", async () => {
    const saves: Entry[][] = [];
    const m = await createDidMap<Entry>({
      load: [],
      save: async (entries) => {
        saves.push(entries);
      },
    });
    await m.set({ did: "did:plc:a", tier: "basic" });
    expect(m.has("did:plc:a")).toBe(true);
    expect(saves.length).toBe(1);
    expect(saves[0]?.[0]?.did).toBe("did:plc:a");
  });

  it("set() overwrites an existing entry with the same DID", async () => {
    const m = await createDidMap<Entry>({
      load: [{ did: "did:plc:a", tier: "basic" }],
      save: async () => {},
    });
    await m.set({ did: "did:plc:a", tier: "sensitive" });
    expect(m.list().length).toBe(1);
    expect(m.get("did:plc:a")?.tier).toBe("sensitive");
  });

  it("set() rejects and leaves state unchanged if save throws", async () => {
    const m = await createDidMap<Entry>({
      load: [{ did: "did:plc:a" }],
      save: async () => {
        throw new Error("disk full");
      },
    });
    await expect(m.set({ did: "did:plc:b" })).rejects.toThrow("disk full");
    expect(m.has("did:plc:b")).toBe(false);
    expect(m.has("did:plc:a")).toBe(true);
  });

  it("delete() removes and returns true; missing did returns false (no save)", async () => {
    let saveCount = 0;
    const m = await createDidMap<Entry>({
      load: [{ did: "did:plc:a" }],
      save: async () => {
        saveCount++;
      },
    });
    expect(await m.delete("did:plc:a")).toBe(true);
    expect(m.has("did:plc:a")).toBe(false);
    expect(saveCount).toBe(1);

    expect(await m.delete("did:plc:never")).toBe(false);
    expect(saveCount).toBe(1); // not incremented
  });

  it("set() fires onChange with the new entries", async () => {
    const m = await createDidMap<Entry>({ load: [], save: async () => {} });
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));
    await m.set({ did: "did:plc:a" });
    expect(fires.length).toBe(1);
    expect(fires[0]?.[0]?.did).toBe("did:plc:a");
  });

  it("file-backed + save: a set() does not cause a double onChange from the subsequent mtime-poll", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([]));
    const m = await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
      save: async (entries) => {
        // Caller writes through. Simulate atomic write here.
        await writeFile(path, JSON.stringify(entries));
        // Bump mtime so the file looks "changed" to a naive poller.
        await bumpMtime(path);
      },
    });
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));

    await m.set({ did: "did:plc:a" });

    // Give the poll loop a few cycles to potentially fire again.
    await new Promise((r) => setTimeout(r, 200));

    // We only want ONE change event for the set, not a second from the poll
    // seeing our own write.
    expect(fires.length).toBe(1);
    m.close();
  });

  // A save that is still running after it wrote the file leaves a window in
  // which a poll tick sees the new mtime before set()/delete() records it.
  // Holding the save open past a poll interval makes that window certain.
  async function slowSaveMap(path: string): Promise<DidMapMutable<Entry>> {
    return await createDidMap<Entry>({
      load: { path, parse: JSON.parse },
      pollMs: 30,
      save: async (entries) => {
        await writeFile(path, JSON.stringify(entries));
        await bumpMtime(path);
        await new Promise((r) => setTimeout(r, 80));
      },
    });
  }

  it("file-backed + slow save: a set() fires one onChange even when a poll lands during the save", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([]));
    const m = await slowSaveMap(path);
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));

    await m.set({ did: "did:plc:a" });
    await new Promise((r) => setTimeout(r, 200));

    expect(fires.length).toBe(1);
    expect(m.has("did:plc:a")).toBe(true);
    m.close();
  });

  it("file-backed + slow save: a delete() fires one onChange even when a poll lands during the save", async () => {
    const path = join(dir, "list.json");
    await writeFile(path, JSON.stringify([{ did: "did:plc:a" }]));
    const m = await slowSaveMap(path);
    const fires: Entry[][] = [];
    m.onChange((es) => fires.push(es));

    expect(await m.delete("did:plc:a")).toBe(true);
    await new Promise((r) => setTimeout(r, 200));

    expect(fires.length).toBe(1);
    expect(m.has("did:plc:a")).toBe(false);
    m.close();
  });
});

// ── read-only (save omitted) ────────────────────────────────────────────

describe("createDidMap: read-only (save omitted)", () => {
  it("returned object has no set/delete (type-level + runtime)", async () => {
    const m = await createDidMap<Entry>({ load: [{ did: "did:plc:a" }] });
    // Type-level: TS would reject `m.set(...)` if uncast; at runtime the
    // property simply isn't there.
    expect("set" in m).toBe(false);
    expect("delete" in m).toBe(false);
    m.close();
  });
});

// ── onChange wiring ─────────────────────────────────────────────────────

describe("createDidMap: onChange + close", () => {
  it("onChange returns a disposer that detaches the listener", async () => {
    const m = await createDidMap<Entry>({ load: [], save: async () => {} });
    let fires = 0;
    const off = m.onChange(() => fires++);
    await m.set({ did: "did:plc:a" });
    expect(fires).toBe(1);
    off();
    await m.set({ did: "did:plc:b" });
    expect(fires).toBe(1);
  });

  it("a listener that throws doesn't break other listeners", async () => {
    const m = await createDidMap<Entry>({ load: [], save: async () => {} });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    let secondFired = 0;
    m.onChange(() => {
      throw new Error("bad listener");
    });
    m.onChange(() => secondFired++);
    await m.set({ did: "did:plc:a" });
    expect(secondFired).toBe(1);
    warn.mockRestore();
  });

  it("close() clears listeners (no further notifications)", async () => {
    const m = await createDidMap<Entry>({ load: [], save: async () => {} });
    let fires = 0;
    m.onChange(() => fires++);
    m.close();
    // Manually invoke set after close — should still work, listener cleared
    await m.set({ did: "did:plc:a" });
    expect(fires).toBe(0);
  });
});

// ── type-narrowing smoke test ──────────────────────────────────────────
//
// These aren't runtime assertions per se — they make sure the overloads
// narrow correctly. If TypeScript starts handing back the wrong type for
// either branch, the assignment lines below would fail to compile and
// `npm run build` would catch it.

describe("createDidMap: type narrowing", () => {
  it("save → DidMapMutable (set/delete present)", async () => {
    const m: DidMapMutable<Entry> = await createDidMap<Entry>({
      load: [],
      save: async () => {},
    });
    void m.set;
    void m.delete;
  });

  it("no save → DidMapReadOnly (no set/delete on the type)", async () => {
    const m: DidMapReadOnly<Entry> = await createDidMap<Entry>({ load: [] });
    // @ts-expect-error — set is intentionally absent from DidMapReadOnly
    void m.set;
    // @ts-expect-error — delete is intentionally absent from DidMapReadOnly
    void m.delete;
  });
});
