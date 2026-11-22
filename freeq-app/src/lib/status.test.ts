import { describe, it, expect } from 'vitest';
import { agentContext, agentFacts, elapsedSince, parseAgentStatus, parseAwayStatus, stateLabel } from './status';

const RAW = 'project=phoenix-agent doing=answering+chad-bot-phoenix+in+#phoenix+·+0s';

describe('parseAgentStatus', () => {
  it('decodes the harness-kit key=value status', () => {
    expect(parseAgentStatus(RAW)).toEqual({
      project: 'phoenix-agent',
      doing: 'answering chad-bot-phoenix in #phoenix',
    });
  });

  it('drops the frozen elapsed count older agents bake into doing', () => {
    // "· 0s" was the age when it was sent, and stayed on screen for minutes.
    expect(parseAgentStatus('doing=answering+chad+·+12m')?.doing).toBe('answering chad');
    expect(parseAgentStatus('doing=fixing+the+·+separator')?.doing).toBe('fixing the · separator');
  });

  it('reads when the work began, so a client can count up live', () => {
    expect(parseAgentStatus('doing=answering+chad since=1790769600')).toEqual({
      doing: 'answering chad',
      since: 1790769600_000,
    });
    expect(parseAgentStatus('doing=x since=soon')?.since).toBeUndefined();
  });

  it('takes the presence state off an AWAY reason', () => {
    expect(parseAgentStatus(`executing: ${RAW} model=opus branch=main`)).toMatchObject({
      state: 'executing', project: 'phoenix-agent', model: 'opus', branch: 'main',
    });
  });

  it('leaves free text, JSON and unknown keys alone', () => {
    expect(parseAgentStatus('out to lunch')).toBeNull();
    expect(parseAgentStatus('back at 3: see you')).toBeNull();
    expect(parseAgentStatus('{"status":"lunch"}')).toBeNull();
    expect(parseAgentStatus('a=b c=d')).toBeNull();
    expect(parseAgentStatus('')).toBeNull();
    expect(parseAgentStatus(null)).toBeNull();
  });
});

describe('parseAwayStatus', () => {
  it('reads an agent away line as words', () => {
    expect(parseAwayStatus(`executing: ${RAW}`)).toBe('Working · answering chad-bot-phoenix in #phoenix');
    expect(parseAwayStatus('executing: project=x model=m')).toBe('Working · x · m');
  });
  it('keeps people as they were', () => {
    expect(parseAwayStatus('lunch')).toBe('lunch');
    expect(parseAwayStatus('{"status":"lunch","state":"idle"}')).toBe('lunch');
    expect(parseAwayStatus('')).toBeNull();
  });
});

describe('labels', () => {
  it('names states and context', () => {
    expect(stateLabel('waiting_for_input')).toBe('Waiting for input');
    expect(stateLabel('something_new')).toBe('something new');
    expect(agentContext({ project: 'p', branch: 'b', model: 'm' })).toBe('p @b · m');
  });
});

describe('elapsedSince', () => {
  it('is a short live age, and nothing for a start in the future or unknown', () => {
    const t0 = 1_790_769_600_000;
    expect(elapsedSince(t0, t0 + 5_000)).toBe('5s');
    expect(elapsedSince(t0, t0 + 3 * 60_000 + 10_000)).toBe('3m');
    expect(elapsedSince(t0, t0 + 2 * 3600_000)).toBe('2h');
    expect(elapsedSince(undefined, t0)).toBeUndefined();
    // A peer's clock ahead of ours is not "-4s".
    expect(elapsedSince(t0 + 4_000, t0)).toBe('0s');
  });
});

describe('agentFacts', () => {
  it('does not repeat the project when the repo already names it', () => {
    expect(agentFacts({ project: 'writing', repo: 'github.com/chad/writing', branch: 'main' })).toEqual([
      ['Repo', 'github.com/chad/writing'],
      ['Branch', 'main'],
    ]);
    expect(agentFacts({ project: 'site', repo: 'github.com/chad/chadfowler.com', model: 'opus' })).toEqual([
      ['Project', 'site'],
      ['Repo', 'github.com/chad/chadfowler.com'],
      ['Model', 'opus'],
    ]);
  });
});
