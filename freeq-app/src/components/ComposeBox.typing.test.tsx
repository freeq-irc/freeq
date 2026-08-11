// @vitest-environment jsdom
/**
 * What the composer tells the other people in the room.
 *
 * The web client rendered other clients' typing but never sent its own, so a
 * web user composing a message was invisible to the phone and desktop clients
 * sitting in the same channel.
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

function compose() {
  const view = render(<ComposeBox />);
  return view.getByTestId('compose-input') as HTMLTextAreaElement;
}

function type(input: HTMLTextAreaElement, value: string) {
  fireEvent.change(input, { target: { value } });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  s().reset();
  s().setNick('me');
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('telling the channel we are composing', () => {
  beforeEach(() => {
    s().addChannel('#room');
    s().setActiveChannel('#room');
  });

  it('starts typing on the first keystroke', () => {
    type(compose(), 'h');
    expect(client.startTyping).toHaveBeenCalledWith('#room');
  });

  it('says it once per three seconds, however fast the typing', () => {
    const input = compose();
    type(input, 'h');
    type(input, 'he');
    type(input, 'hel');
    expect(client.startTyping).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(3_100);
    type(input, 'hell');
    expect(client.startTyping).toHaveBeenCalledTimes(2);
  });

  it('says nothing for an empty box', () => {
    const input = compose();
    type(input, 'h');
    vi.advanceTimersByTime(3_100);
    type(input, '');
    expect(client.startTyping).toHaveBeenCalledTimes(1);
  });

  it('stops typing when the message goes out', () => {
    const input = compose();
    type(input, 'hi');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(client.sendMessage).toHaveBeenCalledWith('#room', 'hi');
    expect(client.stopTyping).toHaveBeenCalledWith('#room');
  });

  it('starts again immediately after a send, not three seconds later', () => {
    const input = compose();
    type(input, 'hi');
    fireEvent.keyDown(input, { key: 'Enter' });
    type(input, 'more');
    expect(client.startTyping).toHaveBeenCalledTimes(2);
  });

  it('leaves the server buffer alone — it is nobody to type at', () => {
    s().setActiveChannel('server');
    type(compose(), 'hello');
    expect(client.startTyping).not.toHaveBeenCalled();
  });
});

describe('telling a DM peer we are composing', () => {
  it('addresses the same target the message itself goes to', () => {
    s().addChannel('did:plc:bob');
    s().setActiveChannel('did:plc:bob');
    const input = compose();
    type(input, 'hi');
    expect(client.startTyping).toHaveBeenCalledWith('did:plc:bob');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(client.stopTyping).toHaveBeenCalledWith('did:plc:bob');
  });
});
