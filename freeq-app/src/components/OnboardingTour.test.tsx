// @vitest-environment jsdom
/**
 * The first-run tour fits who arrived. A room guest joined from a link with no
 * account, so a tour opening with "your Bluesky login is your chat identity"
 * is wrong for them: they get a short room tour instead, and still see the
 * regular one once they sign in.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, screen, act } from '@testing-library/react';

const guest = vi.hoisted(() => ({ is: false }));
vi.mock('../irc/client', () => ({ isRoomGuest: () => guest.is }));

import { OnboardingTour } from './OnboardingTour';
import { useStore } from '../store';

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  useStore.getState().reset();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function shown() {
  render(<OnboardingTour />);
  await act(async () => { useStore.getState().setRegistered(true); });
  await act(async () => { vi.advanceTimersByTime(2000); });
}

describe('the first-run tour', () => {
  it('opens with AT Protocol identity for a normal sign-in', async () => {
    guest.is = false;
    await shown();
    expect(screen.getByText(/Your Bluesky login is your chat identity/)).toBeTruthy();
  });

  it('tells a room guest what they are, without assuming an account', async () => {
    guest.is = true;
    await shown();
    expect(screen.queryByText(/Your Bluesky login is your chat identity/)).toBeNull();
    expect(screen.getByText(/no account needed/i)).toBeTruthy();
  });

  it('still gives a guest who later signs in the regular tour once', async () => {
    guest.is = true;
    await shown();
    await act(async () => { screen.getByText('Skip').click(); });
    cleanup();
    guest.is = false;
    useStore.getState().reset();
    await shown();
    expect(screen.getByText(/Your Bluesky login is your chat identity/)).toBeTruthy();
  });
});
