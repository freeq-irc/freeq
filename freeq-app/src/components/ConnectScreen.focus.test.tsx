// @vitest-environment jsdom
/**
 * The sign-in screen puts the cursor in the handle box only when the box is
 * empty; the guest nick box still takes it on a switch to guest mode. A
 * sign-in error already set when the screen appears shows as an alert.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, fireEvent, screen } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  connect: () => {},
  setSaslCredentials: () => {},
}));

beforeEach(() => {
  // The screen keeps its guards at module level; each case gets a fresh copy.
  vi.resetModules();
  localStorage.clear();
});

afterEach(() => {
  cleanup();
});

async function showScreen() {
  const { ConnectScreen } = await import('./ConnectScreen');
  render(<ConnectScreen />);
}

describe('the sign-in screen focus', () => {
  it('focuses the handle box when no handle is saved', async () => {
    await showScreen();
    expect(document.activeElement).toBe(screen.getByPlaceholderText('you.bsky.social'));
  });

  it('focuses nothing when a handle is saved', async () => {
    localStorage.setItem('freeq-handle', 'alice.bsky.social');
    await showScreen();
    expect(screen.getByPlaceholderText('you.bsky.social')).toHaveProperty('value', 'alice.bsky.social');
    expect(document.activeElement).toBe(document.body);
  });

  it('focuses the nick box on a switch to guest mode with a handle saved', async () => {
    localStorage.setItem('freeq-handle', 'alice.bsky.social');
    await showScreen();
    fireEvent.click(screen.getByText('Guest'));
    expect(document.activeElement).toBe(screen.getByPlaceholderText('your_nick'));
  });

  it('shows a sign-in error already in the store as an alert', async () => {
    const text = "This device's signing key has expired. Sign in again to continue.";
    const { useStore } = await import('../store');
    useStore.getState().setAuthError(text);
    await showScreen();
    expect(screen.getByRole('alert').textContent).toContain(text);
  });
});
