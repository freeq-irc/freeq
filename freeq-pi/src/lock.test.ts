import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConnectionLock, pidAlive } from "./lock.js";

let dir: string;
let path: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "freeq-lock-"));
  path = ConnectionLock.pathFor(dir);
});

describe("pidAlive", () => {
  it("recognises this process", () => {
    expect(pidAlive(process.pid)).toBe(true);
  });

  it("rejects nonsense and almost-certainly-dead pids", () => {
    for (const pid of [0, -1, 1.5, NaN, 2 ** 30]) expect(pidAlive(pid)).toBe(false);
  });
});

describe("one connection per installation", () => {
  it("grants the lock to the first caller", async () => {
    const a = new ConnectionLock(path);
    const r = await a.acquire("window A");
    expect(r.held).toBe(true);
    expect(a.held).toBe(true);
  });

  it("refuses a second caller while a live process holds it", async () => {
    // pid 1 is a portable stand-in for "a live process that is not us":
    // kill(1, 0) either succeeds or raises EPERM, both of which mean alive.
    // (Our own pid is deliberately exempt, to keep acquire() idempotent.)
    await writeFile(path, JSON.stringify({ pid: 1, at: Date.now(), label: "window A" }));
    const b = new ConnectionLock(path);
    const r = await b.acquire("window B");
    expect(r.held).toBe(false);
    expect(r.holder?.label).toBe("window A");
    expect(b.held).toBe(false);
  });

  it("takes over a stale lock left by a dead process", async () => {
    // A crashed session must not lock the machine out forever.
    await writeFile(path, JSON.stringify({ pid: 2 ** 30, at: 1, label: "crashed" }));
    const b = new ConnectionLock(path);
    expect((await b.acquire("window B")).held).toBe(true);
    const info = JSON.parse(await readFile(path, "utf8"));
    expect(info.pid).toBe(process.pid);
  });

  it("takes over a corrupt lock file", async () => {
    await writeFile(path, "not json at all");
    const b = new ConnectionLock(path);
    expect((await b.acquire()).held).toBe(true);
  });

  it("re-acquires cleanly when the holder is this same process", async () => {
    const a = new ConnectionLock(path);
    await a.acquire("first");
    const again = new ConnectionLock(path);
    expect((await again.acquire("second")).held).toBe(true);
  });

  it("releasing frees it for the next caller", async () => {
    const a = new ConnectionLock(path);
    await a.acquire("A");
    await a.release();
    const b = new ConnectionLock(path);
    expect((await b.acquire("B")).held).toBe(true);
  });

  it("release is a no-op if we never held it", async () => {
    await writeFile(path, JSON.stringify({ pid: 1, at: Date.now(), label: "other" }));
    const b = new ConnectionLock(path);
    await b.acquire();
    await expect(b.release()).resolves.toBeUndefined();
    // The other holder's file survives.
    expect(JSON.parse(await readFile(path, "utf8")).label).toBe("other");
  });

  it("does not delete a successor's lock on release", async () => {
    const a = new ConnectionLock(path);
    await a.acquire("A");
    // A successor overwrites the file (as a takeover would).
    await writeFile(path, JSON.stringify({ pid: 999999, at: Date.now(), label: "successor" }));
    await a.release();
    expect(JSON.parse(await readFile(path, "utf8")).label).toBe("successor");
  });
});
