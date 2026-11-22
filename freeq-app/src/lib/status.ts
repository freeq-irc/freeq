/** An agent's presence status, decoded.
 *
 *  Agents built on harness-kit publish their status as space-separated
 *  `key=value` pairs, with the prose `doing` field's spaces sent as `+`:
 *
 *    project=phoenix-agent model=opus doing=answering+chad+in+#phoenix since=1790769600
 *
 *  Carried in an AWAY reason it is prefixed with the presence state
 *  (`executing: project=…`). Shown raw it is unreadable, so every surface
 *  decodes it with this first.
 */
export interface AgentStatus {
  /** Presence state when the text carried one (`executing`, …). */
  state?: string;
  /** What the agent is doing right now, as prose: the anchor (who it is
   *  answering, what it was asked). */
  doing?: string;
  /** The stage within that ("Running the tests"). */
  step?: string;
  /** The latest action ("bash: npm test"). */
  tool?: string;
  project?: string;
  branch?: string;
  repo?: string;
  model?: string;
  /** When the current work began (epoch ms), for a live "for 3m". */
  since?: number;
}

const KNOWN = new Set(['project', 'branch', 'repo', 'model', 'session', 'doing', 'since', 'step', 'tool']);

/** The elapsed count agents before `since` baked onto `doing` (" · 0s").
 *  It was the age when sent and stayed on screen unchanged, so it is
 *  dropped rather than shown wrong. */
const BAKED_AGE = /\s+·\s+\d+[smhd]$/;
const KV = /^[a-z_]+=\S*$/;

/** Decode an agent's status string, or null when it is not one (free text
 *  from a person, JSON, empty). Never throws. */
export function parseAgentStatus(raw: string | null | undefined): AgentStatus | null {
  if (!raw) return null;
  let text = raw.trim();
  let state: string | undefined;
  const prefixed = /^([a-z_]+):\s+(.*)$/.exec(text);
  if (prefixed && KV.test(prefixed[2]!.split(/\s+/)[0] ?? '')) {
    state = prefixed[1];
    text = prefixed[2]!;
  }
  const tokens = text.split(/\s+/).filter(Boolean);
  if (!tokens.length || !tokens.every((t) => KV.test(t))) return null;
  const out: AgentStatus = {};
  if (state) out.state = state;
  let known = 0;
  for (const tok of tokens) {
    const eq = tok.indexOf('=');
    const k = tok.slice(0, eq);
    const v = tok.slice(eq + 1);
    if (!KNOWN.has(k)) continue;
    known++;
    if (!v) continue;
    if (k === 'doing') out.doing = v.replace(/\+/g, ' ').replace(BAKED_AGE, '');
    else if (k === 'step' || k === 'tool') out[k] = v.replace(/\+/g, ' ');
    else if (k === 'since') {
      if (/^\d{9,11}$/.test(v)) out.since = Number(v) * 1000;
    } else if (k !== 'session') (out as Record<string, string>)[k] = v;
  }
  return known ? out : null;
}

/** Words for an agent presence state. */
export function stateLabel(state: string | undefined): string | undefined {
  if (!state) return undefined;
  const words: Record<string, string> = {
    executing: 'Working',
    active: 'Available',
    online: 'Available',
    idle: 'Idle',
    waiting_for_input: 'Waiting for input',
    blocked_on_permission: 'Needs approval',
    blocked_on_budget: 'Out of budget',
    rate_limited: 'Rate limited',
    degraded: 'Degraded',
    paused: 'Paused',
    sandboxed: 'Sandboxed',
    revoked: 'Revoked',
    offline: 'Offline',
  };
  return words[state] ?? state.replace(/_/g, ' ');
}

/** "phoenix-agent @main · opus": where an agent is working, in one line. */
export function agentContext(s: AgentStatus): string {
  const where = [s.project, s.branch ? `@${s.branch}` : undefined].filter(Boolean).join(' ');
  return [where, s.model].filter(Boolean).join(' · ');
}

/** How long ago `since` was, short ("5s", "3m", "2h"); undefined when
 *  unknown. A start a little in the future (clock skew) reads as 0s. */
export function elapsedSince(since: number | undefined, now: number): string | undefined {
  if (since == null) return undefined;
  const sec = Math.max(0, Math.floor((now - since) / 1000));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}

/** Where an agent works, as labelled facts. The project is left out when
 *  the repo already ends in it (`writing` beside `github.com/chad/writing`
 *  said the same thing twice). */
export function agentFacts(s: AgentStatus): Array<[string, string]> {
  const facts: Array<[string, string]> = [];
  const repoNamesIt = !!(s.project && s.repo && s.repo.split('/').pop()?.toLowerCase() === s.project.toLowerCase());
  if (s.project && !repoNamesIt) facts.push(['Project', s.project]);
  if (s.repo) facts.push(['Repo', s.repo]);
  if (s.branch) facts.push(['Branch', s.branch]);
  if (s.model) facts.push(['Model', s.model]);
  return facts;
}

/** Parse an AWAY reason into display text.
 *
 *  freeq clients may set structured away state as JSON (e.g.
 *  `{"status":"lunch","state":"idle"}`); agents send their `key=value`
 *  status (decoded to "Working · answering chad in #phoenix"); plain IRC
 *  clients send free text. Returns the human-readable status string, or
 *  null when there's nothing to show (not away / empty reason).
 */
export function parseAwayStatus(away: string | null | undefined): string | null {
  if (away == null || away === '') return null;
  const agent = parseAgentStatus(away);
  if (agent) {
    return [stateLabel(agent.state), agent.doing ?? (agentContext(agent) || undefined)]
      .filter(Boolean)
      .join(' · ') || null;
  }
  try {
    const j = JSON.parse(away);
    return j.status || j.state || away;
  } catch {
    return away;
  }
}
