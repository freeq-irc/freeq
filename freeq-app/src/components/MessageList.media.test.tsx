// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { MessageContent } from './MessageList';
import type { Message } from '../store';

afterEach(cleanup);

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

  it('renders an inline <img> for a /api/v1/space-media/*.png URL', () => {
    const url = `${ORIGIN}/api/v1/space-media/YXQ6Ly9leGFtcGxl/photo.png`;
    const { container } = render(<MessageContent msg={msg(url)} />);
    const img = container.querySelector('img');
    expect(img).not.toBeNull();
    expect(img?.getAttribute('src')).toBe(url);
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
