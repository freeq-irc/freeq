/**
 * Safe markdown renderer for messages with +freeq.at/mime=text/markdown.
 *
 * Uses react-markdown (remark AST → React elements, no innerHTML).
 * Only allows safe URL schemes. Raw HTML is disabled.
 */
import { memo } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import type { Components } from 'react-markdown';

const ALLOWED_URL_SCHEMES = /^https?:\/\//i;

/** Sanitize a URL — only allow http/https schemes. */
function sanitizeUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  if (ALLOWED_URL_SCHEMES.test(url)) return url;
  // Allow relative URLs and anchors
  if (url.startsWith('/') || url.startsWith('#')) return url;
  return undefined;
}

const components: Components = {
  // Links: sanitize href, open in new tab
  a: ({ href, children, ...props }) => {
    const safe = sanitizeUrl(href);
    if (!safe) return <span>{children}</span>;
    return (
      <a
        href={safe}
        target="_blank"
        rel="noopener noreferrer"
        className="text-accent hover:underline break-all"
        {...props}
      >
        {children}
      </a>
    );
  },
  // Code blocks with syntax highlighting class
  code: ({ className, children, ...props }) => {
    const isBlock = className?.startsWith('language-');
    if (isBlock) {
      return (
        <pre className="bg-surface rounded px-2 py-1.5 my-1 text-[13px] font-mono overflow-x-auto whitespace-pre-wrap">
          <code className={className} {...props}>{children}</code>
        </pre>
      );
    }
    return (
      <code className="bg-surface px-1 py-0.5 rounded text-[13px] font-mono text-pink" {...props}>
        {children}
      </code>
    );
  },
  // Block-level pre (wraps code blocks)
  pre: ({ children }) => <>{children}</>,
  // Images: sanitize src, constrain size
  img: ({ src, alt, ...props }) => {
    const safe = sanitizeUrl(src);
    if (!safe) return <span>[image: {alt}]</span>;
    return (
      <img
        src={safe}
        alt={alt || ''}
        className="max-w-md max-h-80 rounded mt-1"
        loading="lazy"
        {...props}
      />
    );
  },
  // Paragraphs
  p: ({ children }) => <p className="my-1">{children}</p>,
  // Headers — scale down for chat context
  h1: ({ children }) => <p className="text-lg font-bold my-1">{children}</p>,
  h2: ({ children }) => <p className="text-base font-bold my-1">{children}</p>,
  h3: ({ children }) => <p className="text-sm font-bold my-1">{children}</p>,
  h4: ({ children }) => <p className="text-sm font-semibold my-1">{children}</p>,
  h5: ({ children }) => <p className="text-sm font-medium my-1">{children}</p>,
  h6: ({ children }) => <p className="text-sm font-medium text-fg-muted my-1">{children}</p>,
  // Lists
  ul: ({ children }) => <ul className="list-disc list-inside my-1 space-y-0.5">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal list-inside my-1 space-y-0.5">{children}</ol>,
  li: ({ children }) => <li className="text-[15px]">{children}</li>,
  // Blockquote
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-accent pl-3 my-1 text-fg-muted italic">
      {children}
    </blockquote>
  ),
  // Horizontal rule
  hr: () => <hr className="border-border my-2" />,
  // Tables (GFM)
  table: ({ children }) => (
    <div className="overflow-x-auto my-1">
      <table className="text-sm border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="border-b border-border">{children}</thead>,
  tbody: ({ children }) => <tbody>{children}</tbody>,
  tr: ({ children }) => <tr className="border-b border-border/50">{children}</tr>,
  th: ({ children }) => <th className="px-2 py-1 text-left font-semibold text-fg-muted">{children}</th>,
  td: ({ children }) => <td className="px-2 py-1">{children}</td>,
  // Strong / emphasis
  strong: ({ children }) => <strong>{children}</strong>,
  em: ({ children }) => <em>{children}</em>,
  del: ({ children }) => <del className="text-fg-dim">{children}</del>,
};

interface Props {
  text: string;
}

export const MarkdownMessage = memo(function MarkdownMessage({ text }: Props) {
  return (
    <div className="text-[15px] leading-relaxed [&_pre]:my-1 [&_a]:break-all markdown-message">
      <Markdown
        remarkPlugins={[remarkGfm, remarkBreaks]}
        components={components}
        // Disable raw HTML passthrough (XSS prevention)
        skipHtml
      >
        {text}
      </Markdown>
    </div>
  );
});
