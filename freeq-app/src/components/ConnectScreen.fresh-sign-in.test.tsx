// @vitest-environment jsdom
/**
 * Only the connect made from a returned sign-in is a new sign-in. A connect
 * from a saved broker session is not.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';

const seen = vi.hoisted(() => ({ connects: [] as unknown[][] }));

vi.mock('../irc/client', () => ({
  connect: (...args: unknown[]) => {
    seen.connects.push(args);
  },
  setSaslCredentials: () => {},
}));

beforeEach(() => {
  // The screen keeps its guards at module level; each case gets a fresh copy.
  vi.resetModules();
  localStorage.clear();
  seen.connects = [];
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function showScreen() {
  const { ConnectScreen } = await import('./ConnectScreen');
  render(<ConnectScreen />);
}

describe('the connect screen', () => {
  it('connects a returned sign-in as a new sign-in', async () => {
    localStorage.setItem(
      'freeq-oauth-result',
      JSON.stringify({
        did: 'did:plc:fresh',
        handle: 'alice.bsky.social',
        web_token: 'WT',
        broker_token: 'BT',
        _ts: Date.now(),
      }),
    );
    await showScreen();
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(seen.connects[0]![3]).toBe(true);
  });

  it('connects a saved broker session as not a new sign-in', async () => {
    localStorage.setItem('freeq-broker-token', 'BT');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({ token: 'WT', nick: 'alice', did: 'did:plc:fresh', handle: 'alice.bsky.social' }),
      ),
    );
    await showScreen();
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(seen.connects[0]![3] ?? false).toBe(false);
  });
});
