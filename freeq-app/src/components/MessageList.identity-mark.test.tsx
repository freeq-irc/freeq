// @vitest-environment jsdom
/**
 * The ✓ identity mark beside a row's name opens what the name opens: the
 * same nick-click, with the same arguments.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, screen, fireEvent } from '@testing-library/react';

const { opened } = vi.hoisted(() => ({ opened: [] as Record<string, unknown>[] }));

vi.mock('../irc/client', () => ({
  getNick: () => 'me',
  getClient: () => null,
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

// The popover the nick-click opens, recording what it was opened with.
vi.mock('./UserPopover', () => ({
  UserPopover: (props: Record<string, unknown>) => {
    opened.push(props);
    return null;
  },
}));

const { MessageList } = await import('./MessageList');
const { useStore } = await import('../store');

const s = () => useStore.getState();
const DID = 'did:plc:k2n3e2vsihf3farequ44t5j7';
const ID = '01M00000000000000000000001';

beforeEach(() => {
  s().reset();
  opened.length = 0;
});
afterEach(cleanup);

/** What the popover was opened with, less its close handler. */
function lastOpened() {
  const { onClose: _onClose, ...rest } = opened[opened.length - 1]!;
  return rest;
}

describe('the ✓ beside the name', () => {
  it('calls the row’s nick-click with the arguments a click on the name passes', () => {
    s().addMember('#ident', { nick: 'alice', did: DID });
    s().addMessage('#ident', {
      id: ID,
      from: 'alice',
      text: 'hello',
      timestamp: new Date(10_000_000),
      tags: { account: DID, msgid: ID },
    });
    s().setActiveChannel('#ident');
    render(<MessageList />);

    fireEvent.click(screen.getByText('alice', { selector: 'button' }), { clientX: 20, clientY: 30 });
    const fromName = lastOpened();
    expect(fromName.nick).toBe('alice');

    const mark = screen.getByTitle('AT Protocol identity — click for proof');
    expect(mark.tagName).toBe('BUTTON');
    fireEvent.click(mark, { clientX: 20, clientY: 30 });
    expect(opened).toHaveLength(2);
    expect(lastOpened()).toEqual(fromName);
  });
});
