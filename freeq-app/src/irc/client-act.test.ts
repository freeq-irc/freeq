// @vitest-environment jsdom
/**
 * The bridge's task-event wiring: an `actEvent` off the SDK reaches the
 * store's task map, and a DM one gets a buffer to land in.
 */
import { describe, it, expect, beforeEach } from 'vitest';

const storage = new Map<string, string>();
// @ts-expect-error mock
globalThis.localStorage = {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => storage.set(k, v),
  removeItem: (k: string) => { storage.delete(k); },
  clear: () => storage.clear(),
  get length() { return storage.size; },
  key: (i: number) => [...storage.keys()][i] ?? null,
};
Object.defineProperty(globalThis, 'crypto', {
  value: { randomUUID: () => 'uuid-' + Math.random().toString(36).slice(2), subtle: {} },
  writable: true, configurable: true,
});
// @ts-expect-error mock
globalThis.window = { localStorage: globalThis.localStorage, location: { hash: '', origin: 'http://localhost' }, addEventListener: () => {} };

const { useStore } = await import('../store');
const { __wireEventsForTests } = await import('./client');

/** Stub client that records `.on` registrations and can fire them. */
function makeEventStub() {
  const handlers = new Map<string, Array<(...args: any[]) => void>>();
  return {
    nick: 'me',
    on(event: string, fn: (...args: any[]) => void) {
      const list = handlers.get(event) ?? [];
      list.push(fn);
      handlers.set(event, list);
    },
    emit(event: string, ...args: any[]) {
      for (const fn of handlers.get(event) ?? []) fn(...args);
    },
    opts: { url: 'ws://test' },
  };
}

const OPENER = '01JOPENER00000000000000000';

function actEvent(channel: string) {
  return {
    channel,
    from: 'poster',
    did: 'did:plc:poster',
    kind: 'handoff',
    verb: 'offer',
    eventId: OPENER,
    taskId: OPENER,
    fields: { act: 'handoff', 'act-verb': 'offer', 'act-title': 'ship the release' },
    tags: {},
    replayed: false,
  };
}

beforeEach(() => {
  storage.clear();
  useStore.getState().reset();
});

describe('actEvent wiring', () => {
  it('files a channel task event in that channel', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);
    useStore.getState().addChannel('#work');

    stub.emit('actEvent', actEvent('#work'));

    const task = useStore.getState().channels.get('#work')!.actTasks.get(OPENER)!;
    expect(task.title).toBe('ship the release');
    expect(task.verb).toBe('offer');
  });

  it('opens a DM buffer for a task event sent direct', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);

    stub.emit('actEvent', actEvent('poster'));

    const ch = useStore.getState().channels.get('poster');
    expect(ch?.actTasks.get(OPENER)?.title).toBe('ship the release');
  });
});
