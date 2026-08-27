// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';
import { MessageContent } from './MessageList';
import type { Message } from '../store';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

function msg(text: string): Message {
  return {
    id: 'm1',
    from: 'alice',
    text,
    timestamp: new Date(0),
    tags: {},
  };
}

const ORIGIN = window.location.origin;

describe('private media (capability URL) rendering', () => {
  it('renders an inline <img> for a /api/v1/media/*.jpg URL', () => {
    const url = `${ORIGIN}/api/v1/media/abc123/SIGSIGSIG/photo.jpg`;
    const { container } = render(<MessageContent msg={msg(url)} />);
    const img = container.querySelector('img');
    expect(img).not.toBeNull();
    expect(img?.getAttribute('src')).toBe(url);
  });

  it('fetches space media with the session bearer instead of using the raw URL', async () => {
    // The server serves space media only to channel members, and membership
    // rides on the Authorization header, which an <img src> cannot send. The
    // bytes are fetched and handed to the tag as an object URL instead.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9leGFtcGxl/photo.png`;
    // A hand-rolled stand-in: jsdom's Blob is not the one undici's Response
    // accepts, and only `ok` and `blob()` are read here.
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => new Blob(['bytes'], { type: 'image/png' }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const createObjectURL = vi.fn().mockReturnValue('blob:mock-object-url');
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = vi.fn();

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() => expect(container.querySelector('img')).not.toBeNull());

    expect(fetchMock).toHaveBeenCalledWith(url, expect.anything());
    expect(container.querySelector('img')?.getAttribute('src')).toBe('blob:mock-object-url');
  });

  it('says who can see it when space media is refused', async () => {
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9leGFtcGxl/secret.png`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 403, blob: async () => new Blob() }),
    );

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() =>
      expect(container.textContent).toContain('only visible to members of this channel'),
    );
    expect(container.querySelector('img')).toBeNull();
  });

  it('does not blame the viewer when the fetch itself breaks', async () => {
    // A 502 says nothing about who is asking, so telling them they are not a
    // member would be a guess, and a wrong one for a member reading history.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9leGFtcGxl/oops.png`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 502, blob: async () => new Blob() }),
    );

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() => expect(container.textContent).toContain('could not be loaded'));
    expect(container.textContent).not.toContain('members of this channel');
  });

  it('renders an inline <video> for a /api/v1/media/*.mp4 URL', () => {
    const url = `${ORIGIN}/api/v1/media/def456/SIGSIGSIG/clip.mp4`;
    const { container } = render(<MessageContent msg={msg(url)} />);
    const video = container.querySelector('video');
    expect(video).not.toBeNull();
  });

  it('does not gate same-origin private media behind the external-media setting', () => {
    // loadExternalMedia defaults to false; a /api/v1/media/ URL is first-party
    // so the <img> must render directly rather than a "click to load" button.
    const url = `${ORIGIN}/api/v1/media/ghi789/SIGSIGSIG/cat.png`;
    const { container } = render(<MessageContent msg={msg(url)} />);
    expect(container.querySelector('img')).not.toBeNull();
  });
});
