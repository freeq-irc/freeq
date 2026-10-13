// @vitest-environment jsdom
/**
 * The DM side panel and the one way the app takes a DM peer's DID.
 *
 * The SDK is a stub whose nick→DID lookup is the roster scan the app gives
 * the real SDK as its fallback, so these run the app's own code from the
 * thread key to the DID.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

vi.mock('../lib/profiles', () => ({
  fetchProfile: vi.fn(async () => null),
  getCachedProfile: () => undefined,
}));
vi.mock('./Toast', () => ({ showToast: vi.fn() }));

const { useStore } = await import('../store');
const { __setClientForTests, dmPeerDid } = await import('../irc/client');
const { findMemberByKey } = await import('../lib/identity');

const AGENT_DID = 'did:key:z6MkagentAgentAgentAgentAgentAgentAgent';
const AGENT_NICK = 'nap-freeq-cc';
const WHOIS_DID = 'did:plc:fromwhois';

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
