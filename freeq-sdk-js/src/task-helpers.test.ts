/** The five old task helpers, now thin wrappers over the act sender.
 *
 *  Its own file on purpose: each helper warns once per process, and a fresh
 *  module registry is what lets that be tested at all.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// ── WebSocket mock ────────────────────────────────────────────────

type ReadyState = 0 | 1 | 2 | 3;

class MockWebSocket {
  static CONNECTING: ReadyState = 0;
  static OPEN: ReadyState = 1;
  static CLOSING: ReadyState = 2;
  static CLOSED: ReadyState = 3;

  static instances: MockWebSocket[] = [];

  CONNECTING: ReadyState = 0;
  OPEN: ReadyState = 1;
  CLOSING: ReadyState = 2;
  CLOSED: ReadyState = 3;

  url: string;
  readyState: ReadyState = 0;
  bufferedAmount = 0;
  sent: string[] = [];

  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
    });
  }

  send(data: string): void {
    if (this.readyState !== 1) return;
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.({});
  }

  recv(line: string): void {
    this.onmessage?.({ data: line + '\r\n' });
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  // @ts-expect-error mock global
  globalThis.WebSocket = MockWebSocket;
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function flushAsync(): Promise<void> {
  for (let i = 0; i < 12; i++) await new Promise((r) => setTimeout(r, 0));
}

const CAPS = 'message-tags freeq.at/msgsig';
const DID = 'did:plc:eliza';
const TASK = '01JABCDEF000000000000000EF';

/** A registered client with a real session key, so a task event can be
 *  signed and put on the wire. */
async function signingClient(): Promise<{
  client: import('./client.js').FreeqClient;
  ws: MockWebSocket;
}> {
  const { FreeqClient } = await import('./client.js');
  const client = new FreeqClient({
    url: 'wss://test/irc',
    nick: 'eliza',
    skipInitialBrokerRefresh: true,
  });
  client.signing.setSigningDid(DID);
  await client.signing.generateSigningKey();
  client.connect();
  await flushAsync();
  const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
  ws.recv(`:srv CAP * LS :${CAPS}`);
  await flushAsync();
  ws.recv(`:srv CAP * ACK :${CAPS}`);
  await flushAsync();
  ws.recv(':srv 001 eliza :Welcome');
  await flushAsync();
  ws.sent.length = 0;
  return { client, ws };
}

/** The act TAGMSGs on the wire, as tag maps, in order. */
function actEvents(ws: MockWebSocket): Record<string, string>[] {
  return ws.sent
    .filter((l) => l.includes('TAGMSG') && l.includes('+freeq.at/act='))
    .map((line) => {
      const tags: Record<string, string> = {};
      for (const pair of line.slice(1, line.indexOf(' ')).split(';')) {
        const eq = pair.indexOf('=');
        tags[pair.slice(0, eq)] = pair.slice(eq + 1);
      }
      return tags;
    });
}

// First in the file on purpose: the warning fires once per process, so only
// the first call through `createTask` can observe it.
describe('deprecation', () => {
  it('warns once per helper per process, naming the replacement', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { client } = await signingClient();

    await client.createTask('#ops', 'first');
    await client.createTask('#ops', 'second');

    const mine = warn.mock.calls
      .map((c) => String(c[0]))
      .filter((m) => m.includes('createTask'));
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatch(/deprecated/);
    expect(mine[0]).toMatch(/sendAct/);
    expect(mine[0]).toMatch(/actTags/);
  });
});

describe('createTask', () => {
  it('opens a handoff directed at the sender and takes it', async () => {
    const { client, ws } = await signingClient();
    const taskId = await client.createTask('#ops', 'Build a todo app');
    await flushAsync();

    const events = actEvents(ws);
    expect(events).toHaveLength(2);

    const [offer, accept] = events as [Record<string, string>, Record<string, string>];
    expect(offer['+freeq.at/act']).toBe('handoff');
    expect(offer['+freeq.at/act-verb']).toBe('offer');
    expect(offer['+freeq.at/act-title']).toBe('Build\\sa\\stodo\\sapp');
    expect(offer['+freeq.at/act-to']).toBe(DID);
    expect(offer['+freeq.at/from']).toBe(DID);
    // An opener names no action — its own id becomes the action's.
    expect(offer['+freeq.at/act-id']).toBeUndefined();
    expect(offer['+freeq.at/eventid']).toBe(taskId);

    expect(accept['+freeq.at/act-verb']).toBe('accept');
    expect(accept['+freeq.at/act-id']).toBe(taskId);
    expect(accept['+freeq.at/from']).toBe(DID);
  });

  it('returns the offer’s id, a ULID', async () => {
    const { client } = await signingClient();
    const taskId = await client.createTask('#ops', 'anything');
    expect(taskId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });
});

describe('the other four helpers', () => {
  it('updateTask reports progress with the phase in the note', async () => {
    const { client, ws } = await signingClient();
    await client.updateTask('#ops', TASK, 'designing', 'Chose React');
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-verb']).toBe('progress');
    expect(ev['+freeq.at/act-id']).toBe(TASK);
    expect(ev['+freeq.at/act-note']).toBe('designing:\\sChose\\sReact');
  });

  it('completeTask completes and carries a result URL as context', async () => {
    const { client, ws } = await signingClient();
    await client.completeTask('#ops', TASK, 'shipped', 'https://e.g/build/9');
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-verb']).toBe('complete');
    expect(ev['+freeq.at/act-id']).toBe(TASK);
    expect(ev['+freeq.at/act-note']).toBe('shipped');
    expect(ev['+freeq.at/act-ctx']).toBe('https://e.g/build/9');
  });

  it('completeTask without a URL carries no context', async () => {
    const { client, ws } = await signingClient();
    await client.completeTask('#ops', TASK, 'shipped');
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-ctx']).toBeUndefined();
  });

  it('failTask fails with the error as the note', async () => {
    const { client, ws } = await signingClient();
    await client.failTask('#ops', TASK, 'Out of memory');
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-verb']).toBe('fail');
    expect(ev['+freeq.at/act-id']).toBe(TASK);
    expect(ev['+freeq.at/act-note']).toBe('Out\\sof\\smemory');
  });
});

describe('attachEvidence', () => {
  it('hashes the content it is given', async () => {
    const { client, ws } = await signingClient();
    await client.attachEvidence('#ops', TASK, 'test_result', '12/12 passed', {
      reference: 'https://e.g/report.txt',
      content: new TextEncoder().encode('12/12 passed'),
    });
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-verb']).toBe('progress');
    expect(ev['+freeq.at/act-id']).toBe(TASK);
    expect(ev['+freeq.at/act-note']).toBe('test_result:\\s12/12\\spassed');
    expect(ev['+freeq.at/act-ctx']).toBe('https://e.g/report.txt');
    // sha256 over the content bytes, lowercase hex, `sha256:`-prefixed.
    expect(ev['+freeq.at/act-ctx-h']).toBe(
      'sha256:' + (await sha256Hex(new TextEncoder().encode('12/12 passed'))),
    );
  });

  it('sends an unfetchable reference with no hash', async () => {
    const { client, ws } = await signingClient();
    await client.attachEvidence('#ops', TASK, 'artifact_link', 'the built bundle', {
      reference: 'freeq:blob/cap/abc',
    });
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-ctx']).toBe('freeq:blob/cap/abc');
    expect(ev['+freeq.at/act-ctx-h']).toBeUndefined();
  });

  it('hashes a URL it fetched', async () => {
    const body = new TextEncoder().encode('fetched bytes');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, arrayBuffer: async () => body.buffer })),
    );
    const { client, ws } = await signingClient();
    await client.attachEvidence('#ops', TASK, 'deploy_log', 'Deployed', {
      url: 'https://e.g/deploy.log',
    });
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-ctx']).toBe('https://e.g/deploy.log');
    expect(ev['+freeq.at/act-ctx-h']).toBe('sha256:' + (await sha256Hex(body)));
  });

  it('sends the link with no hash when the fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('CORS');
      }),
    );
    const { client, ws } = await signingClient();
    await client.attachEvidence('#ops', TASK, 'deploy_log', 'Deployed', {
      url: 'https://e.g/deploy.log',
    });
    await flushAsync();
    const [ev] = actEvents(ws) as [Record<string, string>];
    expect(ev['+freeq.at/act-ctx']).toBe('https://e.g/deploy.log');
    expect(ev['+freeq.at/act-ctx-h']).toBeUndefined();
  });
});

describe('a session that cannot sign', () => {
  it('throws rather than sending an unsigned task event', async () => {
    const { FreeqClient } = await import('./client.js');
    const client = new FreeqClient({
      url: 'wss://test/irc',
      nick: 'guest',
      skipInitialBrokerRefresh: true,
    });
    client.connect();
    await flushAsync();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]!;
    ws.recv(':srv 001 guest :Welcome');
    await flushAsync();
    ws.sent.length = 0;

    await expect(client.createTask('#ops', 'anything')).rejects.toThrow(
      /must be signed|authenticate/i,
    );
    expect(actEvents(ws)).toHaveLength(0);
  });
});

/** Lowercase hex sha-256, the way the helper spells `act-ctx-h`'s digest. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
