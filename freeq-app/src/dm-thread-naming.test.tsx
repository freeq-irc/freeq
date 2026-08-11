// @vitest-environment jsdom
/**
 * A DM thread is keyed by the peer's DID, and its title is resolved at render
 * time from the SDK's learned DID→nick map. A peer who was never seen joining
 * is named only by their first message, so the title has to survive the name
 * arriving after the thread has already drawn.
 *
 * Live symptom (2026-08-10): a thread with a did:key bot titled `key:z6Mk…7JuZ`
 * while the preview line under it read `claimtestbot: echo: hey`.
 *
 * The app half of that chain already works, and these tests were green when
 * first written — they are here to keep it that way. What breaks them is an
 * innocent-looking optimisation: `updateMemberDid` returning early when the
 * peer is in no channel roster (the cold-DM case is exactly that), which would
 * stop the store notifying and freeze every title mid-render. The half that
 * was actually broken is in the SDK, which learned the binding silently.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, screen, act, waitFor } from '@testing-library/react';

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

vi.mock('./lib/profiles', () => ({
  getCachedProfile: () => undefined,
  fetchProfile: vi.fn(async () => null),
  prefetchProfiles: vi.fn(),
}));
vi.mock('./components/Toast', () => ({ showToast: vi.fn() }));

const { useStore } = await import('./store');
const { __setClientForTests } = await import('./irc/client');

const BOT_DID = 'did:key:z6MkfPfooBarBazQuuxWibbleWobbleFlimFlam7JuZ';
const BOT_NICK = 'claimtestbot';

const s = () => useStore.getState();

/** A stand-in for the SDK client, naming only what its map has learned. */
function clientKnowing(bindings: Map<string, string>) {
  return {
    nick: 'me',
    getNickForDid: (did: string) => bindings.get(did),
    getDidForNick: (nick: string) => {
      for (const [d, n] of bindings) if (n === nick.toLowerCase()) return d;
      return undefined;
    },
    on: () => {},
    off: () => {},
    requestHistory: () => {},
    requestWhois: () => {},
  } as any;
}

beforeEach(() => {
  storage.clear();
  s().reset();
});

afterEach(() => {
  cleanup();
  __setClientForTests(null);
  vi.restoreAllMocks();
});

describe('a late-learned binding reaches the thread title', () => {
  it('notifies subscribers when the peer belongs to no channel we hold', () => {
    // The cold-DM case: we share no channel with this peer, so there is no
    // member record anywhere for the binding to land in.
    s().addChannel(BOT_DID);

    let notified = 0;
    const unsub = useStore.subscribe(() => { notified++; });
    s().updateMemberDid(BOT_NICK, BOT_DID);
    unsub();

    expect(
      notified,
      'learning a name must be an observable change, or nothing showing that peer re-renders',
    ).toBeGreaterThan(0);
  });

  it('still records the DID on a member we do hold', () => {
    s().addChannel('#room');
    s().addMember('#room', { nick: BOT_NICK });

    s().updateMemberDid(BOT_NICK, BOT_DID);

    expect(s().channels.get('#room')!.members.get(BOT_NICK)!.did).toBe(BOT_DID);
  });
});

describe('the sidebar thread title', () => {
  it('heals from the raw DID to the nick when the binding is learned', async () => {
    const bindings = new Map<string, string>();
    __setClientForTests(clientKnowing(bindings));

    s().addChannel(BOT_DID);
    const { Sidebar } = await import('./components/Sidebar');
    render(<Sidebar onOpenSettings={() => {}} />);

    // Before anything names the peer, the thread can only show the DID.
    expect(screen.getByText('key:z6Mk…7JuZ')).toBeTruthy();

    // Their first message arrives; the SDK learns the binding and says so.
    act(() => {
      bindings.set(BOT_DID, BOT_NICK);
      s().updateMemberDid(BOT_NICK, BOT_DID);
    });

    expect(
      screen.queryByText('key:z6Mk…7JuZ'),
      'the thread must stop wearing a raw DID the moment the nick is knowable',
    ).toBeNull();
    expect(screen.getByText(BOT_NICK)).toBeTruthy();
  });
});

describe('the other surfaces that name a DID-keyed thread', () => {
  it('the conversation header heals with the same event', async () => {
    const bindings = new Map<string, string>();
    __setClientForTests(clientKnowing(bindings));

    s().addChannel(BOT_DID);
    s().setActiveChannel(BOT_DID);
    const { MessageList } = await import('./components/MessageList');
    render(<MessageList />);

    // The view shows a loading skeleton for its first 600ms.
    await waitFor(() => expect(screen.getByText(/Conversation with key:z6Mk…7JuZ/)).toBeTruthy(), {
      timeout: 3000,
    });

    act(() => {
      bindings.set(BOT_DID, BOT_NICK);
      s().updateMemberDid(BOT_NICK, BOT_DID);
    });

    expect(screen.getByText(`Conversation with ${BOT_NICK}`)).toBeTruthy();
    expect(screen.queryByText(/Conversation with key:z6Mk…7JuZ/)).toBeNull();
  });
});
