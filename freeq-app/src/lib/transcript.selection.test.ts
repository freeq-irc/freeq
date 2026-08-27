// @vitest-environment jsdom
/**
 * What a block-copy takes when most of the conversation is not on screen.
 *
 * The message list mounts a window of the rows it holds, so a selection the
 * reader drags across a long run of messages has an element at each end and
 * nothing in between. The rows in the copy come from the held list.
 */
import { describe, it, expect } from 'vitest';
import { rowsInSelection } from './transcript';
import type { Message } from '../store';

const HELD: Message[] = Array.from({ length: 200 }, (_, i) => ({
  id: `row-${String(i).padStart(5, '0')}`,
  from: 'alice',
  text: `line ${i}`,
  timestamp: new Date(10_000_000 + i),
  tags: {},
}));

/** Mount only the rows named, the way a windowed list does, and select from
 *  the first named to the last. */
function selectionAcross(mounted: string[], from: string, to: string): Selection {
  document.body.innerHTML = mounted
    .map((id) => `<div id="msg-${id}"><span>row</span></div>`)
    .join('');
  const sel = window.getSelection()!;
  sel.removeAllRanges();
  // Not a Range: a reader dragging upwards leaves the anchor after the focus,
  // which a Range cannot hold — it collapses instead.
  sel.setBaseAndExtent(
    document.getElementById(`msg-${from}`)!.firstChild!, 0,
    document.getElementById(`msg-${to}`)!.firstChild!, 0,
  );
  return sel;
}

describe('the rows a selection runs across', () => {
  it('include every held row between its ends, mounted or not', () => {
    // The premise: the ends are on screen and nothing between them is.
    const sel = selectionAcross(['row-00000', 'row-00199'], 'row-00000', 'row-00199');

    const rows = rowsInSelection(HELD, sel)!;

    expect(rows.length).toBe(200);
    expect(rows[0].id).toBe('row-00000');
    expect(rows[199].id).toBe('row-00199');
    expect(rows.some((r) => r.id === 'row-00100')).toBe(true);
  });

  it('are the same run whichever way the selection was dragged', () => {
    const sel = selectionAcross(['row-00010', 'row-00020'], 'row-00020', 'row-00010');
    const rows = rowsInSelection(HELD, sel)!;
    expect(rows.map((r) => r.id)).toEqual(
      HELD.slice(10, 21).map((r) => r.id),
    );
  });

  it('are nothing for a selection inside one row', () => {
    const sel = selectionAcross(['row-00005'], 'row-00005', 'row-00005');
    expect(rowsInSelection(HELD, sel)).toBeNull();
  });

  it('are nothing when an end is not a row at all', () => {
    document.body.innerHTML = '<div id="elsewhere"><span>x</span></div><div id="msg-row-00001"><span>y</span></div>';
    const sel = window.getSelection()!;
    sel.removeAllRanges();
    sel.setBaseAndExtent(
      document.getElementById('elsewhere')!.firstChild!, 0,
      document.getElementById('msg-row-00001')!.firstChild!, 0,
    );
    expect(rowsInSelection(HELD, sel)).toBeNull();
  });

  it('are nothing for a row the held list no longer has', () => {
    const sel = selectionAcross(['row-00000', 'row-00199'], 'row-00000', 'row-00199');
    expect(rowsInSelection(HELD.slice(0, 50), sel)).toBeNull();
  });
});
