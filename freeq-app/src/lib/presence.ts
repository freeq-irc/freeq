/** Join, part and quit notices: how the room records people coming and going.
 *
 *  They are the noisiest lines in a channel, so they are hidden unless the
 *  reader asks for them — either one line per event, or each run of them
 *  folded into a single summary. Kicks and other moderation lines are not
 *  presence and are never hidden. */

export type JoinPartDisplay = 'hidden' | 'grouped' | 'all';

export const JOIN_PART_DISPLAYS: readonly JoinPartDisplay[] = ['hidden', 'grouped', 'all'];

/** A system line saying someone joined, left or quit — "alice joined",
 *  "bob left", "carol quit (Ping timeout)". */
const PRESENCE_RE = /^(\S+) (joined|left|quit)( \(.*\))?$/;

export function isPresenceLine(msg: { isSystem?: boolean; text: string }): boolean {
  return !!msg.isSystem && PRESENCE_RE.test(msg.text);
}

/** The setting as stored, or — for someone who never chose — the old
 *  on/off toggle carried over: an explicit "on" was a grouped list. */
export function initialJoinPartDisplay(stored: string | null, legacyShow: string | null): JoinPartDisplay {
  if (stored && (JOIN_PART_DISPLAYS as readonly string[]).includes(stored)) return stored as JoinPartDisplay;
  return legacyShow === 'true' ? 'grouped' : 'hidden';
}

function nameList(nicks: string[]): string {
  const shown = nicks.slice(0, 3).join(', ');
  return nicks.length > 3 ? `${shown} and ${nicks.length - 3} more` : shown;
}

/** One line for a run of presence notices: "nap reconnected 3×" when it is
 *  one person's churn, else "alice, bob joined · carol left". */
export function summarizePresence(run: { text: string }[]): string {
  const joined: string[] = [];
  const left: string[] = [];
  let joins = 0;
  let leaves = 0;
  const everyone = new Set<string>();
  for (const m of run) {
    const match = PRESENCE_RE.exec(m.text);
    if (!match) continue;
    const [, nick, verb] = match;
    everyone.add(nick.toLowerCase());
    if (verb === 'joined') {
      joins++;
      if (!joined.includes(nick)) joined.push(nick);
    } else {
      leaves++;
      if (!left.includes(nick)) left.push(nick);
    }
  }
  if (everyone.size === 1) {
    const nick = joined[0] ?? left[0];
    if (joins > 0 && leaves > 0) return `${nick} reconnected ${Math.min(joins, leaves)}×`;
    if (joins > 0) return `${nick} joined ${joins}×`;
    return `${nick} left ${leaves}×`;
  }
  const said: string[] = [];
  if (joined.length > 0) said.push(`${nameList(joined)} joined`);
  if (left.length > 0) said.push(`${nameList(left)} left`);
  return said.join(' · ');
}
