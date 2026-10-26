// @vitest-environment jsdom
// Replying must survive markdown mode: with both on, the send is still a
// reply, and the mime tag rides it so the reply renders as markdown.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, fireEvent } from '@testing-library/react';

vi.mock('../irc/client', () => ({
  sendMessage: vi.fn(), sendReply: vi.fn(), sendEdit: vi.fn(), sendMarkdown: vi.fn(),
  sendAction: vi.fn(), joinChannel: vi.fn(), partChannel: vi.fn(), setTopic: vi.fn(),
  setMode: vi.fn(), kickUser: vi.fn(), inviteUser: vi.fn(), setAway: vi.fn(),
  rawCommand: vi.fn(), sendWhois: vi.fn(), startTyping: vi.fn(), stopTyping: vi.fn(),
  getClient: () => null,
}));

const { ComposeBox } = await import('./ComposeBox');
const { useStore } = await import('../store');
const client = await import('../irc/client');
const s = () => useStore.getState();

const reply = { msgId: 'ORIG1', from: 'bob', text: 'question?', channel: '#room' };

function compose(view: ReturnType<typeof render>, text: string) {
  const input = view.getByTestId('compose-input') as HTMLTextAreaElement;
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

beforeEach(() => {
  vi.useFakeTimers(); vi.clearAllMocks();
  s().reset(); s().setNick('me'); s().addChannel('#room'); s().setActiveChannel('#room');
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('replying while markdown mode is on', () => {
  it('sends a reply carrying the markdown mime tag', () => {
    s().setReplyTo(reply);
    const view = render(<ComposeBox />);
    fireEvent.click(view.getByTitle('Enable markdown mode'));
    compose(view, '- one\n- two');
    expect(client.sendReply).toHaveBeenCalledWith('#room', 'ORIG1', '- one\n- two', {
      tags: { '+freeq.at/mime': 'text/markdown' },
    });
    expect(client.sendMarkdown).not.toHaveBeenCalled();
  });

  it('clears the reply context afterwards', () => {
    s().setReplyTo(reply);
    const view = render(<ComposeBox />);
    fireEvent.click(view.getByTitle('Enable markdown mode'));
    compose(view, '- one');
    expect(s().replyTo).toBeNull();
  });
});

describe('replying with markdown mode off', () => {
  it('sends a plain reply with no mime tag', () => {
    s().setReplyTo(reply);
    const view = render(<ComposeBox />);
    compose(view, 'an answer');
    expect(client.sendReply).toHaveBeenCalledWith('#room', 'ORIG1', 'an answer', undefined);
  });
});

describe('markdown mode with nothing to reply to', () => {
  it('still sends through sendMarkdown', () => {
    const view = render(<ComposeBox />);
    fireEvent.click(view.getByTitle('Enable markdown mode'));
    compose(view, '# heading');
    expect(client.sendMarkdown).toHaveBeenCalledWith('#room', '# heading');
    expect(client.sendReply).not.toHaveBeenCalled();
  });
});
