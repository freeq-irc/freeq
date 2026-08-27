// @vitest-environment jsdom
/**
 * A bookmark points at a message, not at a channel.
 *
 * Taking one used to open the channel and leave the reader at its live end,
 * with the message they saved somewhere above and no way to it but scrolling.
 * It goes to the message now: the channel opens and the list is asked for
 * that row, which fetches the window around it when the channel does not
 * hold it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, cleanup, screen, fireEvent } from '@testing-library/react';
import { BookmarksPanel } from './BookmarksPanel';
import { useStore } from '../store';

const s = () => useStore.getState();
const MSGID = '01M0AAAAAAAAAAAAAAAAAAAA01';

beforeEach(() => {
  s().reset();
  s().setBookmarksPanelOpen(true);
  // A bookmark in a channel the reader is still in, which is the case this
  // is about: the message is old, not the channel gone.
  s().addChannel('#saved');
  s().addBookmark('#saved', MSGID, 'alice', 'the one worth keeping', new Date(1_700_000_000_000));
});
afterEach(cleanup);

describe('taking a bookmark', () => {
  it('offers to go to the message', () => {
    render(<BookmarksPanel />);
    expect(screen.getByRole('button', { name: 'Go to message' })).toBeTruthy();
  });

  it('opens the channel and asks the list for that row', () => {
    render(<BookmarksPanel />);

    fireEvent.click(screen.getByRole('button', { name: 'Go to message' }));

    expect(s().activeChannel).toBe('#saved');
    expect(s().scrollToMsgId).toBe(MSGID);
  });

  it('closes the panel behind it', () => {
    render(<BookmarksPanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Go to message' }));
    expect(s().bookmarksPanelOpen).toBe(false);
  });

  it('still removes', () => {
    render(<BookmarksPanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(s().bookmarks.length).toBe(0);
  });
});
