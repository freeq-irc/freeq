// @vitest-environment jsdom
/**
 * Tests for /join argument parsing in ComposeBox.
 *
 * Covers the comma-separated channel list, the per-channel keys that follow
 * it, and the # prefix added to a bare channel name.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, fireEvent } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  sendMessage: vi.fn(),
  sendReply: vi.fn(),
  sendEdit: vi.fn(),
  sendMarkdown: vi.fn(),
  sendAction: vi.fn(),
  joinChannel: vi.fn(),
  partChannel: vi.fn(),
  setTopic: vi.fn(),
  setMode: vi.fn(),
  kickUser: vi.fn(),
  inviteUser: vi.fn(),
  setAway: vi.fn(),
  rawCommand: vi.fn(),
  sendWhois: vi.fn(),
  startTyping: vi.fn(),
  stopTyping: vi.fn(),
  getClient: () => null,
}));

const { ComposeBox } = await import('./ComposeBox');
const { useStore } = await import('../store');
const client = await import('../irc/client');

const s = () => useStore.getState();

/** Type a command into the composer and submit it. */
function run(command: string) {
  const input = render(<ComposeBox />).getByTestId('compose-input') as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: command } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  s().reset();
  s().setNick('me');
  s().addChannel('#room');
  s().setActiveChannel('#room');
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('/join', () => {
  it('passes a key as a key, not as part of the channel name', () => {
    run('/join #general hunter2');
    expect(client.joinChannel).toHaveBeenCalledWith('#general', 'hunter2');
  });

  it('joins without a key when none is given', () => {
    run('/join #general');
    expect(client.joinChannel).toHaveBeenCalledWith('#general', undefined);
  });

  it('pairs each key with the channel in the same position', () => {
    run('/join #a,#b,#c k1,,k3');
    expect(client.joinChannel).toHaveBeenNthCalledWith(1, '#a', 'k1');
    expect(client.joinChannel).toHaveBeenNthCalledWith(2, '#b', undefined);
    expect(client.joinChannel).toHaveBeenNthCalledWith(3, '#c', 'k3');
  });

  it('still prefixes a bare channel name with #', () => {
    run('/join general hunter2');
    expect(client.joinChannel).toHaveBeenCalledWith('#general', 'hunter2');
  });

  it('reads a space after a comma as part of the list, not as a key', () => {
    run('/join #a, #b');
    expect(client.joinChannel).toHaveBeenNthCalledWith(1, '#a', undefined);
    expect(client.joinChannel).toHaveBeenNthCalledWith(2, '#b', undefined);
  });

  it('takes spaced-out channels and keys together', () => {
    run('/join #a , #b k1, k2');
    expect(client.joinChannel).toHaveBeenNthCalledWith(1, '#a', 'k1');
    expect(client.joinChannel).toHaveBeenNthCalledWith(2, '#b', 'k2');
  });
});
