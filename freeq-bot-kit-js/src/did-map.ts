// createDidMap — a hot-reloadable, DID-keyed map.
//
// Three source flavors:
//   - File-backed:  { path, parse }      → auto mtime-poll
//   - Function:     () => Promise<T[]>   → manual .reload()
//   - Static array: T[]                  → never reloads
//
// Mutation (set/delete) is gated on `save` being provided. Without `save`
// the returned object is read-only — no .set/.delete on the type — which
// makes "mutate without persisting" impossible by construction.
//
// What the framework owns:
//   - Initial load
//   - mtime polling for file sources (interval-based; fs.watch is too flaky
//     across platforms and editor save patterns)
//   - Atomic in-memory swap on reload (no torn reads from concurrent
//     .has / .get calls)
//   - ENOENT-as-empty (the file just hasn't been created yet)
//   - Parse-error retention on RELOAD (keep previous good state + warn;
//     initial parse errors still throw because starting with unknown state
//     is worse than starting with empty)
//   - Self-write tracking so a .set() doesn't cause a redundant onChange
//     when the poll subsequently notices the file changed
//
// What the framework does NOT do:
//   - Pick what membership means (allowlist vs banlist vs roles is wiring)
//   - Pick a file format (caller's `parse`/serialization is theirs)
//   - Validate DID syntax (caller's `parse` decides what's valid)

import { readFile, stat } from "node:fs/promises";
import { log } from "@freeq/sdk";

/** Discriminated source: file (auto-watched), function (manual reload), or
 *  a static array (no reload). */
export type DidMapSource<T> =
  | { path: string; parse: (raw: string) => T[] }
  | (() => Promise<T[]>)
  | T[];

export type DidMapSave<T> = (entries: T[]) => Promise<void>;

export interface DidMapBaseOptions<T extends { did: string }> {
  load: DidMapSource<T>;
  /** mtime-poll interval for file sources. Ignored for function/array
   *  sources. Default 2000ms. */
  pollMs?: number;
}

export interface DidMapMutableOptions<T extends { did: string }>
  extends DidMapBaseOptions<T> {
  /** Persist callback invoked after every successful `set`/`delete`. Caller
   *  owns the write semantics (atomic JSON write, DB UPDATE, etc.). */
  save: DidMapSave<T>;
}

export interface DidMapReadOnly<T extends { did: string }> {
  /** Membership predicate. */
  has(did: string): boolean;
  /** Entry for `did`, or null. */
  get(did: string): T | null;
  /** Snapshot copy of current entries. */
  list(): T[];
  /** Force a re-read. For file sources this re-runs `parse(readFile())`;
   *  for function sources it re-runs the loader; for arrays it's a no-op. */
  reload(): Promise<void>;
  /** Subscribe to entries-changed events (file reload, function reload,
   *  set, delete). Returns a disposer. */
  onChange(cb: (entries: T[]) => void): () => void;
  /** Stop polling, drop subscribers. The map's getters keep working with
   *  the last-known state, but nothing will refresh them. */
  close(): void;
}

export interface DidMapMutable<T extends { did: string }>
  extends DidMapReadOnly<T> {
  /** Upsert by DID. Awaits `save(newEntries)` before mutating in-memory;
   *  rejects if save throws (in-memory state stays unchanged). */
  set(entry: T): Promise<void>;
  /** Remove by DID. Returns false if the DID wasn't present (no save call,
   *  no state change). */
  delete(did: string): Promise<boolean>;
}

// ── Public factory ─────────────────────────────────────────────────────

/** With `save`: full CRUD. */
export function createDidMap<T extends { did: string }>(
  opts: DidMapMutableOptions<T>,
): Promise<DidMapMutable<T>>;
/** Without `save`: read-only-with-reload. */
export function createDidMap<T extends { did: string }>(
  opts: DidMapBaseOptions<T>,
): Promise<DidMapReadOnly<T>>;
export async function createDidMap<T extends { did: string }>(
  opts: DidMapBaseOptions<T> & { save?: DidMapSave<T> },
): Promise<DidMapReadOnly<T> | DidMapMutable<T>> {
  const pollMs = opts.pollMs ?? 2000;
  const source = opts.load;
  const isFile = isFileSource<T>(source);

  let entries: T[] = [];
  let byDid = new Map<string, T>();
  const listeners = new Set<(entries: T[]) => void>();
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let lastMtime: number | null = null;

  const swap = (next: T[]): void => {
    entries = next;
    byDid = new Map(next.map((e) => [e.did, e]));
    for (const cb of listeners) {
      try {
        cb(entries);
      } catch (err) {
        // A bad listener shouldn't break the others.
        // eslint-disable-next-line no-console
        log.warn(`[did-map] onChange listener threw: ${(err as Error).message}`);
      }
    }
  };

  const read = async (): Promise<T[]> => {
    if (Array.isArray(source)) return source;
    if (typeof source === "function") return source();
    try {
      const raw = await readFile(source.path, "utf8");
      return source.parse(raw);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  };

  const refreshMtime = async (): Promise<void> => {
    if (!isFile) return;
    try {
      const s = await stat((source as { path: string }).path);
      lastMtime = s.mtimeMs;
    } catch {
      lastMtime = null;
    }
  };

  // Initial load. Parse errors here propagate — refusing to start with
  // unknown state is safer than starting with empty.
  swap(await read());
  if (isFile) await refreshMtime();

  if (isFile) {
    const filePath = (source as { path: string }).path;
    pollTimer = setInterval(() => {
      void (async (): Promise<void> => {
        let mtime: number | null;
        try {
          const s = await stat(filePath);
          mtime = s.mtimeMs;
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") {
            // File deleted. Swap to empty if we had anything.
            if (lastMtime !== null) {
              lastMtime = null;
              swap([]);
            }
            return;
          }
          // Other stat error: skip this tick.
          return;
        }
        if (mtime === lastMtime) return;
        try {
          const fresh = await read();
          lastMtime = mtime;
          swap(fresh);
        } catch (err) {
          // Parse error on reload: retain previous state, log once per
          // failure. Operator notices via the warning; next correct edit
          // picks up.
          // eslint-disable-next-line no-console
          log.warn(
            `[did-map] reload failed for ${filePath}: ${(err as Error).message}. Retaining previous state.`,
          );
        }
      })();
    }, pollMs);
    pollTimer.unref?.();
  }

  const base: DidMapReadOnly<T> = {
    has: (did) => byDid.has(did),
    get: (did) => byDid.get(did) ?? null,
    list: () => [...entries],
    reload: async () => {
      const fresh = await read();
      swap(fresh);
      if (isFile) await refreshMtime();
    },
    onChange: (cb) => {
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    },
    close: () => {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      listeners.clear();
    },
  };

  if (opts.save) {
    const save = opts.save;
    const mutable: DidMapMutable<T> = {
      ...base,
      set: async (entry) => {
        const next = entries.filter((e) => e.did !== entry.did);
        next.push(entry);
        await save(next);
        swap(next);
        // Re-baseline the mtime so the next poll doesn't see our own write
        // as a change and trigger a redundant onChange.
        if (isFile) await refreshMtime();
      },
      delete: async (did) => {
        if (!byDid.has(did)) return false;
        const next = entries.filter((e) => e.did !== did);
        await save(next);
        swap(next);
        if (isFile) await refreshMtime();
        return true;
      },
    };
    return mutable;
  }

  return base;
}

// ── Helpers ────────────────────────────────────────────────────────────

function isFileSource<T>(s: DidMapSource<T>): s is { path: string; parse: (raw: string) => T[] } {
  return typeof s === "object" && !Array.isArray(s) && "path" in s;
}
