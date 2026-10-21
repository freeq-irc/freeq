// @vitest-environment jsdom
/**
 * Which channels a connection joins. An explicit sign-in — a returned AT
 * sign-in or a guest connect — joins what the person typed in the channel
 * field. A restored session is a reconnect, so it goes back to the channels
 * the browser was last in.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

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

/** The channels argument of the one connect the screen made. */
function joined(): unknown {
  return seen.connects[0]![2];
}

describe('the channels a connect screen sign-in joins', () => {
  it('joins the typed channel on a returned sign-in, not the saved set', async () => {
    // What doAtLogin saved before the redirect, and where this browser was.
    localStorage.setItem('freeq-channels', '#typed');
    localStorage.setItem('freeq-joined-channels', JSON.stringify(['#old']));
    localStorage.setItem(
      'freeq-oauth-result',
      JSON.stringify({
        did: 'did:plc:fresh',
        handle: 'alice.bsky.social',
        web_token: 'WT',
        _ts: Date.now(),
      }),
    );
    await showScreen();
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#typed']);
  });

  it('joins the typed channel on a guest connect, not the saved set', async () => {
    localStorage.setItem('freeq-joined-channels', JSON.stringify(['#old']));
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    fireEvent.change(screen.getByPlaceholderText('#freeq'), { target: { value: '#typed' } });
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#typed']);
  });

  it('rejoins the saved set on a restored session, not the typed channel', async () => {
    localStorage.setItem('freeq-broker-token', 'BT');
    localStorage.setItem('freeq-channels', '#typed');
    localStorage.setItem('freeq-joined-channels', JSON.stringify(['#old']));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({ token: 'WT', nick: 'alice', did: 'did:plc:fresh', handle: 'alice.bsky.social' }),
      ),
    );
    await showScreen();
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#old']);
  });
});
