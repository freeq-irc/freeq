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
// constructs one to measure the pane and the rows in it. Without one, every
// render of that component throws; with one that reports what jsdom knows —
// nothing has a size, and nothing has an offsetParent — the virtualizer has
// no window to compute and mounts no rows at all, and a component test could
// not see a message.
//
// So this reports a nominal size for every box it is asked about, which is
// enough for a window to exist. The number is arbitrary and means nothing:
// jsdom has no layout, and a test that depends on how many rows fall inside
// a viewport is testing this constant rather than the component.
const NOMINAL_BOX_PX = 20;

if (typeof (globalThis as Record<string, unknown>).ResizeObserver !== 'function') {
  (globalThis as Record<string, unknown>).ResizeObserver = class {
    cb: (entries: unknown[]) => void;
    constructor(cb: (entries: unknown[]) => void) {
      this.cb = cb;
    }
    observe(el: Element) {
      // A virtualizer ignores a box that is not laid out, which in jsdom is
      // every box.
      if (!(el as HTMLElement).offsetParent) {
        Object.defineProperty(el, 'offsetParent', {
          value: document.body, configurable: true,
        });
      }
      // A real one reports after layout, never inside `observe`. Reporting
      // synchronously here lands inside React's own render and the
      // measurement is dropped.
      queueMicrotask(() => {
        this.cb([{ target: el, contentRect: { width: NOMINAL_BOX_PX, height: NOMINAL_BOX_PX } }]);
      });
    }
    unobserve() {}
    disconnect() {}
  };
}
