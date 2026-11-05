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

/** Whether that connect asked for those channels, which decides whether the
 *  first of them to join is the channel the app opens. */
function requested(): unknown {
  return seen.connects[0]![4];
}

describe('the channels a connect screen sign-in joins', () => {
  it('joins the typed channel on a returned sign-in, not the saved set', async () => {
    // What doAtLogin saved before the redirect, and where this browser was.
    localStorage.setItem('freeq-oauth-pending', 'edited');
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
    expect(requested()).toBe(true);
  });

  it('joins the typed channel on a guest connect, not the saved set', async () => {
    localStorage.setItem('freeq-joined-channels', JSON.stringify(['#old']));
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    fireEvent.change(screen.getByPlaceholderText('#general'), { target: { value: '#typed' } });
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#typed']);
    expect(requested()).toBe(true);
  });

  it('asks for nothing when the guest leaves the channel field alone', async () => {
    // The field is pre-filled with where this browser last was, so pressing
    // Connect without touching it is not a request for that channel.
    localStorage.setItem('freeq-channels', '#saved');
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#saved']);
    expect(requested()).toBeFalsy();
  });

  it('asks for nothing on a returned sign-in that left the field alone', async () => {
    // doAtLogin marks the pending sign-in plainly when nobody edited it.
    localStorage.setItem('freeq-oauth-pending', '1');
    localStorage.setItem('freeq-channels', '#saved');
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
    expect(joined()).toEqual(['#saved']);
    expect(requested()).toBeFalsy();
  });

  it('carries an edited field across the sign-in redirect', async () => {
    // Editing the field then signing in with AT: the marker doAtLogin writes
    // is the only thing the returning visit can read it from.
    await showScreen();
    fireEvent.change(screen.getByPlaceholderText('#general'), { target: { value: '#naptest' } });
    fireEvent.change(screen.getByPlaceholderText('you.bsky.social'), {
      target: { value: 'alice.bsky.social' },
    });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200 })));
    fireEvent.click(screen.getByText('Sign in with AT Protocol'));
    await waitFor(() =>
      expect(localStorage.getItem('freeq-oauth-pending')).toBe('edited'),
    );
    expect(localStorage.getItem('freeq-channels')).toBe('#naptest');
  });

  it('joins and asks for #general on a first-ever visit', async () => {
    // Nothing stored: the field shows the default, and a guest connect takes
    // it as named — there is no last conversation to go back to.
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    const field = screen.getByPlaceholderText('#general') as HTMLInputElement;
    expect(field.value).toBe('#general');
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#general']);
  });

  it('asks for an invite link first, ahead of the saved channels', async () => {
    // Following an `#auto-join=` link names a channel without typing one, so
    // it counts, and it goes first in the field: first named is what opens.
    window.location.hash = '#auto-join=%23party';
    localStorage.setItem('freeq-channels', '#saved');
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#party', '#saved']);
    expect(requested()).toBe(true);
  });

  it('keeps an invited channel first when it is already saved', async () => {
    window.location.hash = '#auto-join=%23saved';
    localStorage.setItem('freeq-channels', '#other,#saved');
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    fireEvent.change(screen.getByPlaceholderText('your_nick'), { target: { value: 'bob' } });
    fireEvent.click(screen.getByText('Connect as Guest'));
    await waitFor(() => expect(seen.connects).toHaveLength(1));
    expect(joined()).toEqual(['#saved', '#other']);
    expect(requested()).toBe(true);
  });

  it('carries an invite across the sign-in redirect', async () => {
    // The invited channel reaches the returning visit through the saved field
    // and the marker, since nothing of this visit's state survives.
    window.location.hash = '#auto-join=%23party';
    localStorage.setItem('freeq-channels', '#saved');
    await showScreen();
    fireEvent.change(screen.getByPlaceholderText('you.bsky.social'), {
      target: { value: 'alice.bsky.social' },
    });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200 })));
    fireEvent.click(screen.getByText('Sign in with AT Protocol'));
    await waitFor(() =>
      expect(localStorage.getItem('freeq-oauth-pending')).toBe('edited'),
    );
    expect(localStorage.getItem('freeq-channels')).toBe('#party,#saved');
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
    // No one asked for them, so the restored session reopens whichever
    // conversation was last open rather than the first channel to join.
    expect(requested()).toBeFalsy();
  });
});
