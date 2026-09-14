// @vitest-environment jsdom
/**
 * Message times are 24-hour in every locale, so the grouped row's hover time
 * fits its gutter.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { formatTime } from './MessageList';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('formatTime', () => {
  it('renders 24-hour time under an en-US locale', () => {
    // formatTime asks for the runtime's default locale; pin it to en-US.
    const original = Date.prototype.toLocaleTimeString;
    vi.spyOn(Date.prototype, 'toLocaleTimeString').mockImplementation(function (
      this: Date,
      _locales?: Intl.LocalesArgument,
      options?: Intl.DateTimeFormatOptions,
    ) {
      return original.call(this, 'en-US', options);
    });
    expect(formatTime(new Date(2026, 8, 14, 17, 30))).toBe('17:30');
  });
});
