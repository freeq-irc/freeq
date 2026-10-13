// @vitest-environment jsdom
/**
 * The DM side panel and the one way the app takes a DM peer's DID.
 *
 * The SDK is a stub whose nick→DID lookup is the roster scan the app gives
 * the real SDK as its fallback, so these run the app's own code from the
 * thread key to the DID.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, screen, act, waitFor } from '@testing-library/react';

vi.mock('../lib/profiles', () => ({
  fetchProfile: vi.fn(async () => null),
  getCachedProfile: () => undefined,
}));
vi.mock('./Toast', () => ({ showToast: vi.fn() }));

const { useStore } = await import('../store');
const { __setClientForTests, dmPeerDid } = await import('../irc/client');
const { findMemberByKey } = await import('../lib/identity');
const { MemberList } = await import('./MemberList');
const { UserPopover } = await import('./UserPopover');

const AGENT_DID = 'did:key:z6MkagentAgentAgentAgentAgentAgentAgent';
const AGENT_NICK = 'nap-freeq-cc';
const WHOIS_DID = 'did:plc:fromwhois';
const CREATOR_DID = 'did:plc:creatorcreatorcreator';
const PERSON_DID = 'did:plc:personpersonperson';
const PERSON_NICK = 'alice';

const actorUrl = (id: string) => `/api/v1/actors/${encodeURIComponent(id)}`;

/** What the server's actor route says about the agent. */
const AGENT_ANSWER = {
  actor_class: 'agent',
  did: AGENT_DID,
  online: true,
  provenance: { creator_did: CREATOR_DID, _verified: true },
  presence: { state: 'active', status: 'reading the brief' },
  heartbeat: { last_seen: '2026-10-13T00:00:00Z', ttl: 60, healthy: true },
};
const PERSON_ANSWER = { actor_class: 'human', did: PERSON_DID, online: true };
const CREATOR_ANSWER = { actor_class: 'human', did: CREATOR_DID, nick: 'nap' };

const ok = (body: unknown) => ({ ok: true, json: async () => body }) as Response;
const notFound = () => ({ ok: false, json: async () => null }) as Response;

/** Stub fetch answering by URL; returns the mock to count calls on. */
function stubFetch(answers: Record<string, () => Promise<Response> | Response>) {
  const f = vi.fn(async (url: string) => (answers[url] ? answers[url]() : notFound()));
  vi.stubGlobal('fetch', f);
  return f;
}
const callsTo = (f: ReturnType<typeof stubFetch>, url: string) =>
  f.mock.calls.filter(([u]) => u === url).length;

/** The agent and a person, both in a shared channel with their DIDs known. */
function seedRoster() {
  s().addChannel('#room');
  s().addMember('#room', { nick: AGENT_NICK, did: AGENT_DID });
  s().addMember('#room', { nick: PERSON_NICK, did: PERSON_DID });
}

function openDm(key: string) {
  s().addChannel(key);
  s().setActiveChannel(key);
  return render(<MemberList />);
}

const s = () => useStore.getState();

/** A stand-in for the SDK client: its nick→DID lookup is the roster scan. */
function stubClient() {
  return {
    nick: 'me',
    getNickForDid: () => undefined,
    getDidForNick: (n: string) => findMemberByKey(useStore.getState().channels, n)?.member.did,
    whois: () => {},
    on: () => {},
    off: () => {},
  } as unknown as Parameters<typeof __setClientForTests>[0];
}

beforeEach(() => {
  s().reset();
  __setClientForTests(stubClient());
});

afterEach(() => {
  cleanup();
  __setClientForTests(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('dmPeerDid', () => {
  it('returns a DID key itself', () => {
    expect(dmPeerDid(AGENT_DID, WHOIS_DID)).toBe(AGENT_DID);
  });

  it('returns the known DID for a nick', () => {
    s().addChannel('#room');
    s().addMember('#room', { nick: AGENT_NICK, did: AGENT_DID });
    expect(dmPeerDid(AGENT_NICK, WHOIS_DID)).toBe(AGENT_DID);
  });

  it('falls back to the WHOIS DID for a nick with none, else undefined', () => {
    expect(dmPeerDid(AGENT_NICK, WHOIS_DID)).toBe(WHOIS_DID);
    expect(dmPeerDid(AGENT_NICK)).toBeUndefined();
  });
});

describe('live presence in the store', () => {
  it('sets presence on that nick in every channel and keeps it through a roster sync', () => {
    seedRoster();
    s().addChannel('#other');
    s().addMember('#other', { nick: AGENT_NICK, did: AGENT_DID });

    s().setUserPresence(AGENT_NICK, { state: 'executing', status: 'cargo test' });

    for (const name of ['#room', '#other']) {
      expect(s().channels.get(name)!.members.get(AGENT_NICK)!.presence)
        .toEqual({ state: 'executing', status: 'cargo test' });
    }
    expect(s().channels.get('#room')!.members.get(PERSON_NICK)!.presence).toBeUndefined();

    s().setMembers('#room', [{ nick: AGENT_NICK, isOp: false, isHalfop: false, isVoiced: false }]);
    expect(s().channels.get('#room')!.members.get(AGENT_NICK)!.presence)
      .toEqual({ state: 'executing', status: 'cargo test' });

    // A JOIN with an account, or a 674 refresh, goes through addMember.
    s().addMember('#room', { nick: AGENT_NICK, did: AGENT_DID });
    expect(s().channels.get('#room')!.members.get(AGENT_NICK)!.presence)
      .toEqual({ state: 'executing', status: 'cargo test' });
  });
});

describe('the DM side panel for an agent', () => {
  it('shows the badge, Presence and Provenance, and no Heartbeat box', async () => {
    seedRoster();
    const f = stubFetch({
      [actorUrl(AGENT_DID)]: () => ok(AGENT_ANSWER),
      [actorUrl(CREATOR_DID)]: () => ok(CREATOR_ANSWER),
    });

    openDm(AGENT_DID);

    expect(await screen.findByText('🤖 Agent')).toBeTruthy();
    expect(screen.getByText('Presence')).toBeTruthy();
    expect(screen.getByText('active')).toBeTruthy();
    expect(screen.getByText('reading the brief')).toBeTruthy();
    expect(screen.getByText('Provenance')).toBeTruthy();
    expect(await screen.findByText('nap')).toBeTruthy();
    expect(screen.queryByText('Heartbeat')).toBeNull();
    expect(callsTo(f, actorUrl(AGENT_DID))).toBe(1);
  });

  it('asks by the DID of a nick-keyed peer found in a shared channel, not by nick', async () => {
    seedRoster();
    const f = stubFetch({ [actorUrl(AGENT_DID)]: () => ok(AGENT_ANSWER) });

    openDm(AGENT_NICK);

    expect(await screen.findByText('🤖 Agent')).toBeTruthy();
    expect(callsTo(f, actorUrl(AGENT_DID))).toBe(1);
    expect(callsTo(f, actorUrl(AGENT_NICK))).toBe(0);
  });

  it('asks nothing by nick for a DID-keyed peer it has no nick for', async () => {
    // In no shared channel and unknown to the client: no nick to ask by.
    const f = stubFetch({});

    openDm(AGENT_DID);
    await waitFor(() => expect(callsTo(f, actorUrl(AGENT_DID))).toBe(1));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });

    expect(callsTo(f, '/api/v1/actors/undefined')).toBe(0);
  });

  it('follows a presence change without reopening, asking again once per change', async () => {
    seedRoster();
    const f = stubFetch({ [actorUrl(AGENT_DID)]: () => ok(AGENT_ANSWER) });

    openDm(AGENT_DID);
    expect(await screen.findByText('active')).toBeTruthy();
    expect(callsTo(f, actorUrl(AGENT_DID))).toBe(1);

    act(() => s().setUserPresence(AGENT_NICK, { state: 'executing', status: 'cargo test' }));
    expect(await screen.findByText('executing')).toBeTruthy();
    expect(screen.getByText('cargo test')).toBeTruthy();
    await waitFor(() => expect(callsTo(f, actorUrl(AGENT_DID))).toBe(2));

    // The same state again is no change: no new request.
    act(() => s().setUserPresence(AGENT_NICK, { state: 'executing', status: 'cargo test' }));
    act(() => s().setUserPresence(AGENT_NICK, { state: 'idle' }));
    expect(await screen.findByText('idle')).toBeTruthy();
    expect(screen.queryByText('cargo test')).toBeNull();
    await waitFor(() => expect(callsTo(f, actorUrl(AGENT_DID))).toBe(3));
  });

  it('keeps the newer answer when an older one lands late, and the badge while asking', async () => {
    seedRoster();
    const pending: Array<(r: Response) => void> = [];
    const f = stubFetch({
      [actorUrl(AGENT_DID)]: () => new Promise<Response>((resolve) => pending.push(resolve)),
    });

    openDm(AGENT_DID);
    await waitFor(() => expect(pending.length).toBe(1));
    act(() => s().setUserPresence(AGENT_NICK, { state: 'executing' }));
    await waitFor(() => expect(pending.length).toBe(2));

    // The newer request answers first, then the older one.
    await act(async () => pending[1](ok(AGENT_ANSWER)));
    expect(await screen.findByText('🤖 Agent')).toBeTruthy();
    await act(async () => pending[0](ok({ ...AGENT_ANSWER, actor_class: 'human' })));
    expect(screen.getByText('🤖 Agent')).toBeTruthy();

    // A new request out does not blank what is shown.
    act(() => s().setUserPresence(AGENT_NICK, { state: 'idle' }));
    await waitFor(() => expect(pending.length).toBe(3));
    expect(screen.getByText('🤖 Agent')).toBeTruthy();
    expect(callsTo(f, actorUrl(AGENT_DID))).toBe(3);
  });
});

describe('the DM side panel for a person', () => {
  it('shows none of the agent pieces once the server has answered', async () => {
    seedRoster();
    const f = stubFetch({ [actorUrl(PERSON_DID)]: () => ok(PERSON_ANSWER) });

    openDm(PERSON_DID);
    await waitFor(() => expect(callsTo(f, actorUrl(PERSON_DID))).toBe(1));
    await act(async () => {});

    expect(screen.queryByText(/🤖/)).toBeNull();
    expect(screen.queryByText('Presence')).toBeNull();
    expect(screen.queryByText('Provenance')).toBeNull();
  });

  it('draws no Presence box for a person\'s /away', async () => {
    seedRoster();
    const f = stubFetch({ [actorUrl(PERSON_DID)]: () => ok(PERSON_ANSWER) });

    openDm(PERSON_DID);
    await waitFor(() => expect(callsTo(f, actorUrl(PERSON_DID))).toBe(1));

    // The web SDK raises `presence` from every AWAY line.
    act(() => s().setUserPresence(PERSON_NICK, { state: 'lunch' }));
    await waitFor(() => expect(callsTo(f, actorUrl(PERSON_DID))).toBe(2));
    await act(async () => {});

    expect(screen.queryByText('Presence')).toBeNull();
    expect(screen.queryByText('lunch')).toBeNull();
  });
});

describe('the popup', () => {
  it('shows the badge, the DID row, then Presence, and no Heartbeat box', async () => {
    seedRoster();
    stubFetch({
      [actorUrl(AGENT_DID)]: () => ok(AGENT_ANSWER),
      [actorUrl(CREATOR_DID)]: () => ok(CREATOR_ANSWER),
    });

    render(<UserPopover nick={AGENT_NICK} did={AGENT_DID} position={{ x: 0, y: 0 }} onClose={() => {}} />);

    const badge = await screen.findByText('🤖 Agent');
    const didRow = screen.getByText(AGENT_DID);
    const presence = screen.getByText('Presence');
    expect(badge.compareDocumentPosition(didRow) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(didRow.compareDocumentPosition(presence) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('Provenance')).toBeTruthy();
    expect(screen.queryByText('Heartbeat')).toBeNull();
  });
});
