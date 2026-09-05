// @vitest-environment jsdom
/**
 * Chat markdown keeps the line breaks the sender typed.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { MarkdownMessage } from './MarkdownRenderer';

afterEach(cleanup);

describe('MarkdownMessage', () => {
  it('renders a line break for each single newline in a paragraph', () => {
    const { container } = render(
      <MarkdownMessage text={'Commands:\n!help - show help\n!status - show status'} />
    );
    expect(container.querySelectorAll('p')).toHaveLength(1);
    expect(container.querySelectorAll('br')).toHaveLength(2);
  });

  it('keeps blank-line-separated text in separate paragraphs', () => {
    const { container } = render(<MarkdownMessage text={'first\n\nsecond'} />);
    expect(container.querySelectorAll('p')).toHaveLength(2);
    expect(container.querySelectorAll('br')).toHaveLength(0);
  });

  it('keeps newlines inside a fenced code block as text, not breaks', () => {
    const { container } = render(
      <MarkdownMessage text={'```sh\nfoo\nbar\n```'} />
    );
    const code = container.querySelector('pre code');
    expect(code?.querySelectorAll('br')).toHaveLength(0);
    expect(code?.textContent).toBe('foo\nbar\n');
  });

  it('still renders GFM tables', () => {
    const { container } = render(
      <MarkdownMessage text={'| a | b |\n| - | - |\n| 1 | 2 |'} />
    );
    expect(container.querySelector('table')).not.toBeNull();
    expect(container.querySelectorAll('td')).toHaveLength(2);
  });
});
