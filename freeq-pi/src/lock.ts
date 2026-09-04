/**
 * One freeq connection per pi installation.
 *
 * Identity is per-installation by design (design doc §7), so every pi window
 * you open would otherwise connect as the SAME did:key and the SAME nick.
 * The server permits that — it treats them as multi-device siblings — but the
 * result is incoherent:
 *
 *   - presence is last-writer-wins, so a window sitting idle overwrites the
 *     "executing" status of the window that is actually working;
 *   - a channel mention is answered by every window at once;
 *   - closing one window produces ghost/rejoin churn for the shared nick.
 *
 * So exactly one session holds the connection. The rest stay passive and say
 * so. This is a lock, not a leader election: no coordination, no heartbeat
 * protocol, just a pid file with a liveness check, which is enough because
 * all contenders are processes on one machine owned by one user.
 */

import { readFile, writeFile, mkdir, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface LockInfo {
  pid: number;
  /** Epoch ms the lock was taken. */
  at: number;
  /** Informational: which session/cwd holds it, for a useful message. */
  label?: string;
}

export interface AcquireResult {
  held: boolean;
  /** Set when another live process holds it. */
  holder?: LockInfo;
}

/** True if a process is alive and ours to reason about. */
export function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    // Signal 0 checks existence/permission without delivering anything.
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means it exists but belongs to someone else — treat as alive.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

export class ConnectionLock {
  #path: string;
  #held = false;

  constructor(path: string) {
    this.#path = path;
  }

  static pathFor(agentDir: string, project?: string): string {
    // One lock per project identity, not per installation. Two windows in the
    // same project are the same agent and must not both speak; two windows in
    // different projects are different agents and must not block each other.
    const suffix = project ? `-${project.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40)}` : "";
    return join(agentDir, `freeq-connection${suffix}.lock`);
  }

  get held(): boolean {
    return this.#held;
  }

  async read(): Promise<LockInfo | undefined> {
    try {
      const raw = JSON.parse(await readFile(this.#path, "utf8")) as unknown;
      if (!raw || typeof raw !== "object") return undefined;
      const o = raw as Record<string, unknown>;
      if (typeof o.pid !== "number") return undefined;
      return {
        pid: o.pid,
        at: typeof o.at === "number" ? o.at : 0,
        label: typeof o.label === "string" ? o.label : undefined,
      };
    } catch {
      return undefined;
    }
  }

  /**
   * Take the lock unless a live process holds it.
   *
   * A lock left behind by a crashed session is stale and taken over — the
   * alternative is a machine that can never connect again after one hard kill.
   */
  async acquire(label?: string): Promise<AcquireResult> {
    const existing = await this.read();
    if (existing && existing.pid !== process.pid && pidAlive(existing.pid)) {
      return { held: false, holder: existing };
    }
    await mkdir(dirname(this.#path), { recursive: true });
    const info: LockInfo = { pid: process.pid, at: Date.now(), label };
    await writeFile(this.#path, `${JSON.stringify(info)}\n`, { mode: 0o600 });
    this.#held = true;
    return { held: true };
  }

  /**
   * Re-assert a lock we believe we hold.
   *
   * The file can vanish under us — a tmp-dir cleaner, an operator tidying up,
   * or (as happened during development) someone deleting what looked like a
   * stale lock while its owner was very much alive. Without this, the slot
   * silently becomes free and the next window connects alongside us, which is
   * exactly the duplicate-session state the lock exists to prevent.
   *
   * Returns false if somebody else now legitimately holds it, in which case
   * the caller should stand down rather than fight.
   */
  async refresh(label?: string): Promise<boolean> {
    if (!this.#held) return false;
    const current = await this.read();
    if (current && current.pid !== process.pid && pidAlive(current.pid)) {
      // Someone took over while we weren't looking. Concede.
      this.#held = false;
      return false;
    }
    if (current && current.pid === process.pid) return true;
    // Missing or stale-but-not-ours: rewrite it.
    const info: LockInfo = { pid: process.pid, at: Date.now(), label };
    await mkdir(dirname(this.#path), { recursive: true });
    await writeFile(this.#path, `${JSON.stringify(info)}\n`, { mode: 0o600 });
    return true;
  }

  /** Release only if we still own it — never stomp a successor. */
  async release(): Promise<void> {
    if (!this.#held) return;
    this.#held = false;
    const current = await this.read();
    if (current && current.pid !== process.pid) return;
    try {
      await unlink(this.#path);
    } catch {
      /* already gone */
    }
  }
}
