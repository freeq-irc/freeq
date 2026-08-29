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

const SERVER = 'did:web:irc.example';

/** The receipt the server signs for a move, as it reaches a client: its own
 *  sender, and the task it confirms. */
function receipt(channel: string, taskId = OPENER, eventId = '01JRECEIPT0000000000000000') {
  return {
    channel,
    from: 'irc.example',
    did: SERVER,
    kind: 'handoff',
    verb: 'confirm',
    eventId,
    taskId,
    fields: { act: 'handoff', 'act-verb': 'confirm', 'act-id': taskId, 'act-subject': OPENER },
    tags: {},
    replayed: false,
  };
}

/** A move by a person on a task this client may or may not hold. */
function followUp(channel: string, taskId: string) {
  return {
    channel,
    from: 'worker',
    did: 'did:plc:worker',
    kind: 'handoff',
    verb: 'progress',
    eventId: '01JPROGRESS000000000000000',
    taskId,
    fields: { act: 'handoff', 'act-verb': 'progress', 'act-id': taskId, 'act-note': 'halfway' },
    tags: {},
    replayed: false,
  };
}

const verbs = (channel: string, taskId = OPENER) =>
  useStore.getState().channels.get(channel)?.actTasks.get(taskId)?.events.map((e) => e.verb);

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

describe('which buffer an act event lands in', () => {
  const DM = 'did:plc:poster';

  it("files the server's receipt in the thread already holding its task", () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);
    stub.emit('actEvent', actEvent(DM));

    // The receipt names the server as its sender, so the SDK can only key it
    // by the server. The task is what says where it belongs.
    stub.emit('actEvent', receipt(SERVER));

    expect(verbs(DM)).toEqual(['offer', 'confirm']);
    expect(useStore.getState().channels.has(SERVER)).toBe(false);
  });

  it('files it there too when the task replays inside a history batch', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);
    useStore.getState().addChannel(DM);
    // The order the SDK produces: the batch's lines, then the events it held
    // back until the batch closed.
    stub.emit('historyBatch', DM, [
      { id: '01JLINE00000000000000000LN', from: 'poster', text: 'offered: ship the release',
        timestamp: new Date(), tags: { '+freeq.at/ref': OPENER } },
    ], undefined);
    stub.emit('actEvent', { ...actEvent(DM), replayed: true });
    stub.emit('actEvent', { ...receipt(SERVER), replayed: true });

    expect(verbs(DM)).toEqual(['offer', 'confirm']);
    expect(useStore.getState().channels.has(SERVER)).toBe(false);
  });

  it('makes no thread for a receipt whose task nobody holds', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);

    stub.emit('actEvent', receipt(SERVER, '01JUNHELD00000000000000000'));

    expect(useStore.getState().channels.has(SERVER)).toBe(false);
    expect(useStore.getState().channels.size).toBe(0);
  });

  it("files a move on a task nobody holds in the sender's own thread", () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);
    useStore.getState().addChannel(DM);

    stub.emit('actEvent', followUp(DM, '01JUNHELD00000000000000000'));

    expect(verbs(DM, '01JUNHELD00000000000000000')).toEqual(['progress']);
  });

  it('makes no thread for a move on a task nobody holds from someone we have none with', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);

    stub.emit('actEvent', followUp('did:plc:stranger', '01JUNHELD00000000000000000'));

    expect(useStore.getState().channels.size).toBe(0);
  });

  it('leaves a channel event in its channel', () => {
    const stub = makeEventStub();
    __wireEventsForTests(stub as any);
    useStore.getState().addChannel('#work');

    stub.emit('actEvent', actEvent('#work'));
    stub.emit('actEvent', followUp('#work', OPENER));
    stub.emit('actEvent', receipt('#work'));

    expect(verbs('#work')).toEqual(['offer', 'progress', 'confirm']);
    expect([...useStore.getState().channels.keys()]).toEqual(['#work']);
  });
});
