// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, waitFor } from '@testing-library/react';

// The fetch helper reads the bearer off the singleton SDK client, so the
// bearer race is only reproducible with that module stubbed.
const mockClient: { apiBearer: string | null } | null = { apiBearer: null };
let currentClient: typeof mockClient = null;
vi.mock('../irc/client', () => ({
  getClient: () => currentClient,
  getNick: () => 'me',
  requestHistory: vi.fn(),
  sendReaction: vi.fn(),
  sendUnreact: vi.fn(),
  joinChannel: vi.fn(),
}));

import { MessageContent } from './MessageList';
import type { Message } from '../store';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  currentClient = null;
  mockClient!.apiBearer = null;
});

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

  it('plays private space audio through the bearer, not a bare <audio src>', async () => {
    // An <audio src> cannot carry the Authorization header any more than an
    // <img src> can, so the same fetch-and-object-URL path has to cover it.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9hdWRpbw/note.m4a`;
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => new Blob(['bytes'], { type: 'audio/mp4' }),
    });
    vi.stubGlobal('fetch', fetchMock);
    URL.createObjectURL = vi.fn().mockReturnValue('blob:audio-object-url');
    URL.revokeObjectURL = vi.fn();

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() => expect(container.querySelector('audio')).not.toBeNull());
    expect(fetchMock).toHaveBeenCalledWith(url, expect.anything());
    expect(container.querySelector('audio')?.getAttribute('src')).toBe('blob:audio-object-url');
  });

  it('offers a private attachment with no inline renderer as a real link', async () => {
    // A .pdf has no player; a plain <a href> would 403 on click in exactly
    // the restricted channels this feature exists for.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9kb2M/report.pdf`;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => new Blob(['bytes'], { type: 'application/pdf' }),
    }));
    URL.createObjectURL = vi.fn().mockReturnValue('blob:doc-object-url');
    URL.revokeObjectURL = vi.fn();

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() => expect(container.querySelector('a')).not.toBeNull());
    const a = container.querySelector('a')!;
    expect(a.getAttribute('href')).toBe('blob:doc-object-url');
    expect(a.getAttribute('download')).toBe('report.pdf');
  });

  it('retries once the session bearer lands instead of calling a member a stranger', async () => {
    // History renders before the API-BEARER notice arrives, so the first
    // fetch can lose the race. Reporting "not a member" then would be both
    // wrong and permanent.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9yYWNl/late.png`;
    currentClient = mockClient;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 403, blob: async () => new Blob() })
      .mockResolvedValue({
        ok: true,
        status: 200,
        blob: async () => new Blob(['bytes'], { type: 'image/png' }),
      });
    vi.stubGlobal('fetch', fetchMock);
    URL.createObjectURL = vi.fn().mockReturnValue('blob:late-object-url');
    URL.revokeObjectURL = vi.fn();

    const { container } = render(<MessageContent msg={msg(url)} />);
    // The bearer turns up a moment later, exactly as it does in the app.
    setTimeout(() => { mockClient!.apiBearer = 'sess-late'; }, 250);

    await waitFor(
      () => expect(container.querySelector('img')?.getAttribute('src')).toBe('blob:late-object-url'),
      { timeout: 3000 },
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(container.textContent).not.toContain('members of this channel');
  });

  it('does not stall on the bearer when there is no connection to wait for', async () => {
    // A logged-out reader has no client at all. Waiting several seconds to
    // tell them something we already know would be pure delay.
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9ndWVzdA/nope.png`;
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 403, blob: async () => new Blob() });
    vi.stubGlobal('fetch', fetchMock);

    const { container } = render(<MessageContent msg={msg(url)} />);
    await waitFor(() =>
      expect(container.textContent).toContain('only visible to members of this channel'),
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});