// @vitest-environment jsdom
/**
 * Who the client says is typing, and where that line lives.
 *
 * Both surfaces were broken in the same way: typing was a flag on a member
 * of the channel roster, so a DM peer (who is on no roster) could never be
 * shown; and the line rendered as the last child of the scrolling transcript,
 * where a reader sitting at the bottom of the scroll never sees it.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { MessageList, TypingIndicatorBar } from './MessageList';
import { useStore } from '../store';

afterEach(cleanup);

const s = () => useStore.getState();

function message(from: string) {
  return { id: 'm-' + from, from, text: 'hi', timestamp: new Date(0), tags: {} };
}

beforeEach(() => {
  s().reset();
  s().setNick('me');
});

describe('who is typing', () => {
  it('names a channel member', () => {
    s().addChannel('#room');
    s().addMember('#room', { nick: 'bob' });
    s().setActiveChannel('#room');
    s().setTyping('#room', 'bob', true);

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toContain('bob is typing');
  });

  it('names a DM peer, who belongs to no member roster', () => {
    s().addChannel('did:plc:bob');
    s().addMessage('did:plc:bob', message('bob'));
    s().setActiveChannel('did:plc:bob');
    s().setTyping('did:plc:bob', 'bob', true);

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toContain('bob is typing');
  });

  it('drops the typing back when the sender says they stopped', () => {
    s().addChannel('#room');
    s().addMember('#room', { nick: 'bob' });
    s().setActiveChannel('#room');
    s().setTyping('#room', 'bob', true);
    s().setTyping('#room', 'bob', false);

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toBe('');
  });

  it('never reports us to ourselves — our own typing echoes back', () => {
    s().addChannel('#room');
    s().addMember('#room', { nick: 'me' });
    s().setActiveChannel('#room');
    s().setTyping('#room', 'me', true);

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toBe('');
  });

  it('counts several typers without naming them all', () => {
    s().addChannel('#room');
    s().setActiveChannel('#room');
    for (const nick of ['bob', 'carol', 'dave']) {
      s().addMember('#room', { nick });
      s().setTyping('#room', nick, true);
    }

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toContain('and 2 others are typing');
  });

  it('speaks only for the buffer on screen', () => {
    s().addChannel('#room');
    s().addChannel('#other');
    s().addMember('#other', { nick: 'bob' });
    s().setActiveChannel('#room');
    s().setTyping('#other', 'bob', true);

    const { container } = render(<TypingIndicatorBar />);
    expect(container.textContent).toBe('');
  });
});

describe('where the typing line lives', () => {
  it('sits outside the scrolling transcript, not below its last message', () => {
    // Appended inside the scroll container, the line lands below the fold for
    // a reader pinned to the bottom: the container grows, nothing scrolls, and
    // the indicator is never on screen. It belongs between the transcript and
    // the composer, as the desktop and phone clients place it.
    s().addChannel('#room');
    s().addMember('#room', { nick: 'bob' });
    s().addMessage('#room', message('bob'));
    s().setActiveChannel('#room');
    s().setTyping('#room', 'bob', true);

    const { container } = render(<MessageList />);
    const scroller = container.querySelector('[data-testid="message-list"]');
    expect(scroller).not.toBeNull();
    expect(scroller!.textContent).not.toContain('is typing');
  });
});
