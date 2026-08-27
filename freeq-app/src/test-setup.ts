// Vitest setup — runs before every test file (see vite.config.ts setupFiles).
//
// vitest's jsdom environment can hand us a `localStorage` whose Storage
// prototype methods are missing (seen with vitest 4.1 + jsdom 29: the global
// exists but `getItem` is undefined), which crashes any import of store.ts —
// it reads persisted UI prefs at module scope. Install a plain in-memory
// Storage ONLY when the environment's own one is broken or absent, so a
// healthy jsdom keeps its real implementation.

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key: string) => (data.has(key) ? data.get(key)! : null),
    key: (index: number) => [...data.keys()][index] ?? null,
    removeItem: (key: string) => void data.delete(key),
    setItem: (key: string, value: string) => void data.set(key, String(value)),
  };
}

for (const name of ['localStorage', 'sessionStorage'] as const) {
  const existing = (globalThis as Record<string, unknown>)[name] as
    | Storage
    | undefined;
  if (typeof existing?.getItem !== 'function') {
    // writable so suites that install their own mock via plain
    // assignment (`globalThis.localStorage = …`) still can.
    Object.defineProperty(globalThis, name, {
      value: memoryStorage(),
      configurable: true,
      writable: true,
    });
  }
}

// jsdom implements no ResizeObserver, and the message list's virtualizer
// constructs one to measure rows. Without it every render of that component
// throws. jsdom also lays nothing out, so a real implementation would only
// ever report zeroes: this observes nothing and reports nothing, which is
// what a zero-height document has to say anyway.
if (typeof (globalThis as Record<string, unknown>).ResizeObserver !== 'function') {
  (globalThis as Record<string, unknown>).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}
