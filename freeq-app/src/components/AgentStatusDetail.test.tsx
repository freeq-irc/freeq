// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, cleanup, screen, act } from '@testing-library/react';
import { AgentStatusDetail } from './UserPopover';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('AgentStatusDetail', () => {
  it('counts up from when the work began instead of showing what was sent', () => {
    vi.useFakeTimers({ now: new Date('2026-09-30T12:00:00Z') });
    const since = Math.floor(Date.now() / 1000) - 90;
    render(
      <AgentStatusDetail
        status={`project=writing repo=github.com/chad/writing branch=main doing=answering+chadfowler.com+in+#chad-compute since=${since}`}
      />,
    );
    const doing = screen.getByTestId('agent-doing');
    expect(doing.textContent).toBe('answering chadfowler.com in #chad-compute · for 1m');
    act(() => {
      vi.advanceTimersByTime(3 * 60_000);
    });
    expect(doing.textContent).toBe('answering chadfowler.com in #chad-compute · for 4m');
    // The repo already says "writing"; it is not listed twice.
    expect(screen.queryByText('Project')).toBeNull();
    expect(screen.getByText('github.com/chad/writing')).toBeTruthy();
  });

  it('shows an older agent without its frozen "· 0s"', () => {
    render(<AgentStatusDetail status="project=writing doing=answering+chad+in+#x+·+0s" />);
    expect(screen.getByTestId('agent-doing').textContent).toBe('answering chad in #x');
  });
});
