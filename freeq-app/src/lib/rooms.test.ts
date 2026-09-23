/**
 * Instant rooms in the browser: key loading, waiting/polling, and steward
 * duty — against a fake server (the REST shapes from docs/INSTANT-ROOMS.md)
 * and a fake client, with the SDK's real group crypto.
 */
import { describe, it, expect, vi } from 'vitest';
import {
  createGroup,
  decodeMultibaseEd25519,
  generateDidKey,
  openSealed,
  sealFor,
  sealedFromWire,
  sealedToWire,
  type ChannelCipher,
  type GroupState,
} from '@freeq/sdk';
import { createRooms, type RoomsClient, type RoomsDeps, type X25519Pair } from './rooms';
import type { RoomState } from '../store';
import type { StorageLike } from './room-link';

const CH = '#r-quiet-copper-fox';
const ME = 'did:plc:me';
const BOB = 'did:plc:bob';

// ── Fixtures ──

async function x25519Pair(): Promise<X25519Pair> {
  const kp = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { secret: fromB64url(jwk.d!), publicKey: fromB64url(jwk.x!) };
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const fromB64url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

function memStorage(): StorageLike & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

/** A pre-key bundle as the server publishes it (X25519 identity + a signed pre-key). */
async function bundleFor(pair: X25519Pair, signing?: { did: string; signer: (b: Uint8Array) => Promise<string> }) {
  const spk = pair.publicKey;
  const bundle: Record<string, unknown> = {
    identity_key: b64(pair.publicKey),
    signed_pre_key: b64(spk),
    spk_signature: b64(new Uint8Array(64)),
    spk_id: 1,
  };
  if (signing) {
    bundle.spk_signature = b64(fromB64url(await signing.signer(spk)));
    bundle.signing_key = b64(decodeMultibaseEd25519(signing.did.slice('did:key:'.length)));
  }
  return bundle;
}

/**
 * The server, as far as rooms are concerned: sealed keys per epoch per DID,
 * a roster, a founder, published bundles. Answers the four endpoints.
 */
class FakeServer {
  founder = ME;
  roster: string[] = [ME];
  /** epoch → did → EGK1 wire */
  keys = new Map<number, Map<string, string>>();
  bundles = new Map<string, Record<string, unknown>>();
  /** DIDs the room endpoint answers for (403 for anyone else). */
  isRoom = true;
  posts: Array<{ epoch: number; dids: string[] }> = [];
  invites = 0;
  bearerToDid = new Map<string, string>([['BEARER-ME', ME]]);

  seal = async (state: GroupState, did: string, pub: Uint8Array) => {
    let m = this.keys.get(state.epoch);
    if (!m) { m = new Map(); this.keys.set(state.epoch, m); }
    m.set(did, sealedToWire(await sealFor(state, pub)));
  };

  latest(): number | null {
    let best: number | null = null;
    for (const e of this.keys.keys()) if (best === null || e > best) best = e;
    return best;
  }

  epochsOf(did: string): number[] {
    const out: number[] = [];
    for (const [e, m] of this.keys) if (m.has(did)) out.push(e);
    return out.sort((a, b) => a - b);
  }

  fetch = async (url: string, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? 'GET';
    const auth = new Headers(init?.headers).get('Authorization') ?? '';
    const caller = this.bearerToDid.get(auth.replace(/^Bearer /, '')) ?? null;
    const u = new URL(url, 'http://test');
    const ch = decodeURIComponent(u.pathname.split('/')[4] ?? '');

    if (/^\/api\/v1\/keys\//.test(u.pathname)) {
      const did = decodeURIComponent(u.pathname.slice('/api/v1/keys/'.length));
      const bundle = this.bundles.get(did);
      return bundle ? Response.json({ bundle }) : Response.json({ error: 'not found' }, { status: 404 });
    }
    if (!caller) return Response.json({ error: 'unauthorized' }, { status: 401 });

    if (u.pathname.endsWith('/groupkeys') && method === 'GET') {
      if (!this.isRoom) return Response.json({ error: 'no' }, { status: 403 });
      const keys = [...this.keys.entries()]
        .filter(([, m]) => m.has(caller))
        .map(([epoch, m]) => ({ epoch, sealed: m.get(caller)! }));
      return Response.json({ channel: ch, keys });
    }
    if (u.pathname.endsWith('/groupkeys') && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as { epoch: number; keys: Record<string, string> };
      const latest = this.latest();
      if ((latest === null || body.epoch > latest) && caller !== this.founder) {
        return Response.json({ error: 'founder only' }, { status: 403 });
      }
      let m = this.keys.get(body.epoch);
      if (!m) { m = new Map(); this.keys.set(body.epoch, m); }
      const skipped: string[] = [];
      for (const [did, wire] of Object.entries(body.keys)) {
        if (!this.roster.includes(did)) { skipped.push(did); continue; }
        m.set(did, wire);
      }
      this.posts.push({ epoch: body.epoch, dids: Object.keys(body.keys) });
      return Response.json({ ok: true, epoch: body.epoch, stored: Object.keys(body.keys).length - skipped.length, skipped });
    }
    if (/^\/api\/v1\/rooms\/[^/]+$/.test(u.pathname) && method === 'GET') {
      if (!this.isRoom) return Response.json({ error: 'not found' }, { status: 404 });
      const room = decodeURIComponent(u.pathname.slice('/api/v1/rooms/'.length));
      return Response.json({
        channel: room,
        topic: null,
        founder_did: this.founder,
        created_at: 1,
        last_activity: 2,
        expires_at: 3,
        latest_epoch: this.latest(),
        members: this.roster.map((did) => ({ did, joined_at: 1, online: true, epochs: this.epochsOf(did) })),
      });
    }
    if (u.pathname.endsWith('/invites') && method === 'POST') {
      this.invites++;
      return Response.json({ invite: `TOK${this.invites}`, url: `http://test/r/${ch.replace(/^#/, '')}#TOK${this.invites}`, invite_expires_at: 99 }, { status: 201 });
    }
    return Response.json({ error: `unhandled ${method} ${u.pathname}` }, { status: 500 });
  };
}

class FakeClient implements RoomsClient {
  apiBearer: string | null = 'BEARER-ME';
  authDid: string | null = ME;
  nick = 'me';
  ciphers = new Map<string, ChannelCipher>();
  setChannelCipher(channel: string, cipher: ChannelCipher | null) {
    if (cipher) this.ciphers.set(channel, cipher); else this.ciphers.delete(channel);
  }
  getChannelCipher(channel: string) { return this.ciphers.get(channel) ?? null; }
}

interface Harness {
  server: FakeServer;
  client: FakeClient;
  me: X25519Pair;
  messages: string[];
  states: Map<string, Partial<RoomState>>;
  storage: ReturnType<typeof memStorage>;
  rooms: ReturnType<typeof createRooms>;
}

async function harness(over: Partial<RoomsDeps> = {}): Promise<Harness> {
  const server = new FakeServer();
  const client = new FakeClient();
  const me = await x25519Pair();
  const messages: string[] = [];
  const states = new Map<string, Partial<RoomState>>();
  const storage = memStorage();
  const rooms = createRooms({
    getClient: () => client,
    fetch: server.fetch,
    identity: () => me,
    systemMessage: (_ch, text) => { messages.push(text); },
    setRoomState: (ch, patch) => { states.set(ch, { ...(states.get(ch) ?? {}), ...patch }); },
    clearRoomState: (ch) => { states.delete(ch); },
    storage,
    sleep: async () => {},
    origin: '',
    pollMs: 1,
    pollMaxMs: 3,
    readyWaitMs: 1000,
    stewardDebounceMs: 0,
    ...over,
  });
  return { server, client, me, messages, states, storage, rooms };
}

/** A steward elsewhere seals `epoch` to us on the server. */
async function sealedToUs(h: Harness, epoch = 1): Promise<GroupState> {
  const state = { ...createGroup(CH), epoch };
  await h.server.seal(state, ME, h.me.publicKey);
  return state;
}

// ── Loading ──

describe('loading a room key', () => {
  it('opens the key sealed to us, installs the cipher and says which epoch', async () => {
    const h = await harness();
    const state = await sealedToUs(h);

    expect(await h.rooms.loadRoomKeys(CH)).toBe(true);

    expect(h.rooms.holdsKey(CH)).toBe(true);
    expect(h.rooms.states(CH).map((s) => s.epoch)).toEqual([1]);
    expect(h.rooms.states(CH)[0].secret).toEqual(state.secret);
    const cipher = h.client.getChannelCipher(CH)!;
    expect(cipher).toBeTruthy();
    const wire = (await cipher.encrypt('hello'))!;
    expect(cipher.isCiphertext(wire)).toBe(true);
    expect(await cipher.decrypt(wire)).toBe('hello');
    expect(h.messages).toContain('🔒 Room key loaded (epoch 1)');
    expect(h.states.get(CH)).toMatchObject({ isRoom: true, hasKey: true, heldEpoch: 1, latestEpoch: 1, founderDid: ME, waiting: false });
  });

  it('persists the opened secret under the DID and channel', async () => {
    const h = await harness();
    const state = await sealedToUs(h);
    await h.rooms.loadRoomKeys(CH);
    const raw = h.storage.getItem(`freeq-room-keys:${ME}:${CH}`);
    expect(raw).toBeTruthy();
    expect(JSON.parse(raw!)).toEqual({ '1': b64(state.secret) });
  });

  it('restores a persisted secret silently when the server has nothing new', async () => {
    const h = await harness();
    const secret = crypto.getRandomValues(new Uint8Array(32));
    h.storage.setItem(`freeq-room-keys:${ME}:${CH}`, JSON.stringify({ '1': b64(secret) }));
    // The server knows epoch 1 exists (sealed to someone else).
    await h.server.seal({ channel: CH, epoch: 1, secret }, BOB, (await x25519Pair()).publicKey);

    expect(await h.rooms.loadRoomKeys(CH)).toBe(true);
    expect(h.rooms.states(CH)[0].secret).toEqual(secret);
    expect(h.messages.some((m) => m.includes('Room key loaded'))).toBe(false);
    expect(h.states.get(CH)).toMatchObject({ hasKey: true, heldEpoch: 1 });
  });

  it('is idempotent while a load is in flight', async () => {
    const h = await harness();
    await sealedToUs(h);
    const a = h.rooms.loadRoomKeys(CH);
    const b = h.rooms.loadRoomKeys(CH);
    expect(a).toBe(b);
    await a;
    expect(h.messages.filter((m) => m.includes('Room key loaded'))).toHaveLength(1);
  });

  it('starts loading on join for a #r- channel and for any +E channel', async () => {
    const h = await harness();
    await sealedToUs(h);
    h.rooms.onChannelJoined(CH, false);
    await vi.waitFor(() => expect(h.rooms.holdsKey(CH)).toBe(true));

    const h2 = await harness();
    h2.rooms.onChannelJoined('#plain', false);
    expect(h2.rooms.holdsKey('#plain')).toBe(false);
    expect(h2.messages).toEqual([]);
  });

  it('does nothing for a guest (no bearer)', async () => {
    const h = await harness({ readyWaitMs: 0 });
    h.client.apiBearer = null;
    expect(await h.rooms.loadRoomKeys(CH)).toBe(false);
    expect(h.messages).toEqual([]);
    expect(h.client.ciphers.size).toBe(0);
  });

  it('leaves a +E channel that is not a room and has no group keys alone', async () => {
    const h = await harness();
    h.server.isRoom = false;
    expect(await h.rooms.loadRoomKeys('#company')).toBe(false);
    expect(h.messages).toEqual([]);
    expect(h.states.size).toBe(0);
  });

  it('says so when the e2ee identity never appears', async () => {
    const h = await harness({ readyWaitMs: 0, identity: () => null });
    expect(await h.rooms.loadRoomKeys(CH)).toBe(false);
    expect(h.messages[0]).toMatch(/identity is not ready/);
  });
});

// ── Waiting ──

describe('waiting for a key', () => {
  it('reports the wait, then picks up a key sealed later', async () => {
    const h = await harness({ pollMaxMs: 1000 });
    h.server.roster = [ME, BOB];
    h.server.founder = BOB;
    let sealNow = false;
    const state = createGroup(CH);
    const origFetch = h.server.fetch;
    // The steward seals to us on the third poll.
    let polls = 0;
    const rooms = createRooms({
      getClient: () => h.client,
      fetch: async (url, init) => {
        if (url.includes('/groupkeys') && (init?.method ?? 'GET') === 'GET' && ++polls === 3) sealNow = true;
        if (sealNow && !h.server.keys.get(1)?.has(ME)) await h.server.seal(state, ME, h.me.publicKey);
        return origFetch(url, init);
      },
      identity: () => h.me,
      systemMessage: (_ch, text) => { h.messages.push(text); },
      setRoomState: (ch, patch) => { h.states.set(ch, { ...(h.states.get(ch) ?? {}), ...patch }); },
      clearRoomState: () => {},
      storage: null,
      sleep: async () => {},
      origin: '',
      pollMs: 1,
      pollMaxMs: 1000,
      readyWaitMs: 1000,
      stewardDebounceMs: 0,
    });

    expect(await rooms.loadRoomKeys(CH)).toBe(false);
    expect(h.messages).toContain('Waiting for a member to seal the room key to you…');
    expect(h.states.get(CH)).toMatchObject({ isRoom: true, hasKey: false, waiting: true });

    await vi.waitFor(() => expect(rooms.holdsKey(CH)).toBe(true));
    expect(h.messages).toContain('🔒 Room key loaded (epoch 1)');
    expect(h.states.get(CH)).toMatchObject({ hasKey: true, heldEpoch: 1, waiting: false });
    expect(h.client.getChannelCipher(CH)).toBeTruthy();
  });

  it('gives up after the poll budget', async () => {
    const h = await harness({ pollMs: 1, pollMaxMs: 3 });
    h.server.founder = BOB;
    h.server.roster = [ME, BOB];
    expect(await h.rooms.loadRoomKeys(CH)).toBe(false);
    await vi.waitFor(() => expect(h.messages.some((m) => m.startsWith('No room key arrived'))).toBe(true));
    expect(h.states.get(CH)).toMatchObject({ hasKey: false, waiting: false });
  });

  it('stops polling when we leave the channel', async () => {
    const h = await harness({ pollMs: 1, pollMaxMs: 1000 });
    h.server.founder = BOB;
    h.server.roster = [ME, BOB];
    await h.rooms.loadRoomKeys(CH);
    h.rooms.onChannelLeft(CH);
    await new Promise((r) => setTimeout(r, 5));
    const fetchesBefore = h.server.posts.length;
    await new Promise((r) => setTimeout(r, 5));
    expect(h.server.posts.length).toBe(fetchesBefore);
    expect(h.states.has(CH)).toBe(false);
    expect(h.messages.some((m) => m.startsWith('No room key arrived'))).toBe(false);
  });
});

// ── Steward ──

describe('steward duty', () => {
  it('seals every held epoch to members lacking the latest, skipping those without a bundle', async () => {
    const h = await harness();
    const bob = await x25519Pair();
    h.server.roster = [ME, BOB, 'did:plc:carol', 'did:plc:dave'];
    h.server.bundles.set(BOB, await bundleFor(bob));
    const e1 = await sealedToUs(h, 1);
    const e2 = await sealedToUs(h, 2);
    // carol already has both; dave has no bundle.
    await h.server.seal(e1, 'did:plc:carol', (await x25519Pair()).publicKey);
    await h.server.seal(e2, 'did:plc:carol', (await x25519Pair()).publicKey);

    // Loading runs the arrival pass (we hold the latest epoch).
    expect(await h.rooms.loadRoomKeys(CH)).toBe(true);

    expect(h.server.posts).toEqual([{ epoch: 1, dids: [BOB] }, { epoch: 2, dids: [BOB] }]);
    for (const [epoch, state] of [[1, e1], [2, e2]] as const) {
      const wire = h.server.keys.get(epoch)!.get(BOB)!;
      const opened = await openSealed(sealedFromWire(wire)!, bob);
      expect(opened?.secret).toEqual(state.secret);
    }
    expect(h.messages).toContain('🔑 Sealed the room key to a new member');

    // A second pass has nothing left to do and says nothing more.
    const before = h.messages.length;
    const res = await h.rooms.stewardPass(CH);
    expect(res.sealed).toEqual([]);
    expect(res.skipped).toEqual([{ did: 'did:plc:dave', reason: 'no pre-key bundle published' }]);
    expect(h.messages.length).toBe(before);
  });

  it('as founder, creates epoch 1 when the room has none and seals it to the roster', async () => {
    const h = await harness();
    const bob = await x25519Pair();
    h.server.roster = [ME, BOB];
    h.server.bundles.set(BOB, await bundleFor(bob));

    expect(await h.rooms.loadRoomKeys(CH)).toBe(true);

    expect(h.server.latest()).toBe(1);
    expect(h.server.posts).toEqual([{ epoch: 1, dids: [ME] }, { epoch: 1, dids: [BOB] }]);
    expect(h.rooms.states(CH).map((s) => s.epoch)).toEqual([1]);
    const mine = h.rooms.states(CH)[0].secret;
    const opened = await openSealed(sealedFromWire(h.server.keys.get(1)!.get(BOB)!)!, bob);
    expect(opened?.secret).toEqual(mine);
    expect(h.messages).toContain('🔑 Created the room key (epoch 1)');
    expect(h.messages.some((m) => m.startsWith('Waiting'))).toBe(false);
    expect(h.states.get(CH)).toMatchObject({ hasKey: true, latestEpoch: 1 });
  });

  it('as a non-founder, does not invent an epoch', async () => {
    const h = await harness({ pollMaxMs: 0 });
    h.server.founder = BOB;
    h.server.roster = [ME, BOB];
    const res = await h.rooms.stewardPass(CH);
    expect(res).toEqual({ sealed: [], skipped: [] });
    expect(h.server.posts).toEqual([]);
  });

  it('hands out nothing when we do not hold the latest epoch', async () => {
    const h = await harness();
    h.server.roster = [ME, BOB];
    h.server.bundles.set(BOB, await bundleFor(await x25519Pair()));
    await sealedToUs(h, 1);
    // Epoch 2 exists on the server, sealed to someone else — not to us.
    await h.server.seal({ ...createGroup(CH), epoch: 2 }, 'did:plc:carol', (await x25519Pair()).publicKey);

    await h.rooms.loadRoomKeys(CH);
    const res = await h.rooms.stewardPass(CH);
    expect(res.sealed).toEqual([]);
    expect(res.skipped).toEqual([{ did: BOB, reason: 'we do not hold epoch 2' }]);
    expect(h.server.posts).toEqual([]);
  });

  it('runs a (debounced) pass when someone joins, only if we hold the latest epoch', async () => {
    const h = await harness();
    await sealedToUs(h, 1);
    await h.rooms.loadRoomKeys(CH);
    expect(h.server.posts).toEqual([]);

    const bob = await x25519Pair();
    h.server.roster = [ME, BOB];
    h.server.bundles.set(BOB, await bundleFor(bob));
    h.rooms.onMemberJoined(CH, 'me'); // our own join: ignored
    h.rooms.onMemberJoined(CH, 'bob');
    h.rooms.onMemberJoined(CH, 'bob'); // coalesced
    await vi.waitFor(() => expect(h.server.posts).toEqual([{ epoch: 1, dids: [BOB] }]));
    await new Promise((r) => setTimeout(r, 5));
    expect(h.server.posts).toHaveLength(1);

    // Not holding the latest: a join triggers nothing.
    const h2 = await harness();
    await sealedToUs(h2, 1);
    await h2.server.seal({ ...createGroup(CH), epoch: 2 }, 'did:plc:carol', (await x25519Pair()).publicKey);
    await h2.rooms.loadRoomKeys(CH);
    h2.server.roster = [ME, BOB];
    h2.server.bundles.set(BOB, await bundleFor(bob));
    h2.rooms.onMemberJoined(CH, 'bob');
    await new Promise((r) => setTimeout(r, 5));
    expect(h2.server.posts).toEqual([]);
  });

  it('binds a did:key member\'s bundle to their key before sealing', async () => {
    const h = await harness();
    await sealedToUs(h, 1);
    const agent = await generateDidKey();
    const impostor = await generateDidKey();
    const agentPair = await x25519Pair();
    const good = agent.did;
    const bad = 'did:key:' + impostor.publicKeyMultibase; // its bundle is signed by `agent`, not by itself
    h.server.roster = [ME, good, bad];
    h.server.bundles.set(good, await bundleFor(agentPair, { did: agent.did, signer: agent.signer }));
    h.server.bundles.set(bad, await bundleFor(await x25519Pair(), { did: agent.did, signer: agent.signer }));

    await h.rooms.loadRoomKeys(CH);
    const res = await h.rooms.stewardPass(CH);
    expect(h.server.posts).toEqual([{ epoch: 1, dids: [good] }]);
    expect(res.skipped).toEqual([{ did: bad, reason: "bundle signing_key is not the did:key's key" }]);
    const opened = await openSealed(sealedFromWire(h.server.keys.get(1)!.get(good)!)!, agentPair);
    expect(opened?.secret).toEqual(h.rooms.states(CH)[0].secret);
  });
});

// ── Leaving, invites ──

describe('leaving and invites', () => {
  it('drops the cipher and in-memory state on leave but keeps the persisted secret', async () => {
    const h = await harness();
    await sealedToUs(h);
    await h.rooms.loadRoomKeys(CH);
    h.rooms.onChannelLeft(CH);
    expect(h.client.getChannelCipher(CH)).toBeNull();
    expect(h.rooms.holdsKey(CH)).toBe(false);
    expect(h.states.has(CH)).toBe(false);
    expect(h.storage.getItem(`freeq-room-keys:${ME}:${CH}`)).toBeTruthy();
  });

  it('mints an invite and remembers its token for the copy button', async () => {
    const h = await harness();
    const res = await h.rooms.createInvite(CH);
    expect(res.invite).toBe('TOK1');
    expect(res.url).toBe('http://test/r/r-quiet-copper-fox#TOK1');
    expect(h.states.get(CH)).toMatchObject({ isRoom: true, inviteToken: 'TOK1' });
  });

  it('refuses to mint an invite when not signed in', async () => {
    const h = await harness();
    h.client.apiBearer = null;
    await expect(h.rooms.createInvite(CH)).rejects.toThrow(/not signed in/);
  });
});
