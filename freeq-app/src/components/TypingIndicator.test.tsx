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

describe('the space the typing line takes', () => {
  // A line that appears and goes takes its height with it, and everything
  // above it — the transcript, and the affordance pinned to the bottom of the
  // pane — moves by that much, twice, every time someone starts and stops.
  // The strip is always there; only its contents come and go.
  function strip() {
    const { container } = render(<TypingIndicatorBar />);
    return container.querySelector('[data-testid="typing-bar"]');
  }

  it('is there when nobody is typing', () => {
    s().addChannel('#quiet');
    s().setActiveChannel('#quiet');

    expect(strip()).not.toBeNull();
  });

  it('is the same box whether or not anyone is typing', () => {
    s().addChannel('#same');
    s().addMember('#same', { nick: 'bob' });
    s().setActiveChannel('#same');
    const quiet = strip()!.className;
    cleanup();

    s().setTyping('#same', 'bob', true);
    const typing = strip()!;

    expect(typing.className).toBe(quiet);
    expect(typing.textContent).toContain('bob is typing');
  });

  it('is there on a buffer that has no typing at all', () => {
    s().setActiveChannel('server');

    expect(strip()).not.toBeNull();
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
