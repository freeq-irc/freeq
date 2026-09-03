/**
 * The seal panel's words, and the tables that pick them.
 *
 * The prose lives in `spec/act-card-copy.json` and this client bundles a copy;
 * the first test pins the two byte-identical. The register and role tables are
 * checked against `spec/act-transitions.json` itself, so a verb added to the
 * rules file cannot quietly go uncovered.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { actRegister, actWhoRole, type ActRegister } from './act-verbs';
import { sealPanelHeader, sealPanelSentence, sealPanelLinkText } from './seal-panel-copy';

const canonicalPath = join(__dirname, '../../../spec/act-card-copy.json');
const rules = JSON.parse(
  readFileSync(join(__dirname, '../../../spec/act-transitions.json'), 'utf8'),
) as {
  kinds: Record<string, {
    opens: { verb: string };
    transitions: { verb: string; from: string | string[]; to: string; who: string }[];
  }>;
};

describe('the bundled copy of the spec file', () => {
  it('is byte-identical to the canonical one', () => {
    const copy = readFileSync(join(__dirname, 'act-card-copy.json'), 'utf8');
    const original = readFileSync(canonicalPath, 'utf8');
    expect(copy, 'refresh with: cp spec/act-card-copy.json freeq-app/src/lib/act-card-copy.json')
      .toBe(original);
  });
});

describe('the panel header', () => {
  it('uppercases the kind off the event tag', () => {
    expect(sealPanelHeader('handoff')).toBe('HANDOFF: Rules Enforced');
    expect(sealPanelHeader('bounty')).toBe('BOUNTY: Rules Enforced');
  });

  it('takes a kind nobody has taught it', () => {
    expect(sealPanelHeader('society-question')).toBe('SOCIETY-QUESTION: Rules Enforced');
  });
});

describe('the link', () => {
  it('is labelled from the spec file', () => {
    expect(sealPanelLinkText()).toBe('View full history');
  });
});

describe('the sentence each role gets', () => {
  it('an opening verb gets the opener sentence', () => {
    expect(sealPanelSentence('offer')).toBe(
      'This opened a task with known rules: who may take it, who may work it, who may finish it. Every later step is checked against those rules before the server accepts it — an illegal step is refused and never appears here.',
    );
  });

  it('an offeree verb gets the offeree sentence', () => {
    const s = 'Only the person this task was offered to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.';
    expect(sealPanelSentence('accept')).toBe(s);
    expect(sealPanelSentence('decline')).toBe(s);
  });

  it('an assignee verb gets the assignee sentence', () => {
    const s = 'Only the worker this task is assigned to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.';
    for (const verb of ['progress', 'complete', 'fail', 'submit', 'forfeit']) {
      expect(sealPanelSentence(verb), verb).toBe(s);
    }
  });

  it('an offerer verb gets the offerer sentence', () => {
    const s = 'Only the person who posted this task could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here.';
    for (const verb of ['cancel', 'award', 'revise', 'accept-work']) {
      expect(sealPanelSentence(verb), verb).toBe(s);
    }
  });

  it('an anyone verb gets the anyone sentence', () => {
    const s = "Any signed-in account could take this step, and the server checked it was legal from the task's current state before accepting it — an illegal step is refused and never appears here.";
    expect(sealPanelSentence('claim')).toBe(s);
    expect(sealPanelSentence('bid')).toBe(s);
  });

  it('a system verb and an unknown verb claim nothing', () => {
    for (const verb of ['confirm', 'expire', 'auto-accept', 'nobody-taught-this']) {
      expect(sealPanelSentence(verb), verb).toBeUndefined();
    }
  });
});

describe('the register table against the rules file', () => {
  /** Every verb the rules file names, with the row it came from. */
  const rows: { verb: string; who: string; from: string | string[]; to: string }[] = [];
  const openers = new Set<string>();
  for (const kind of Object.values(rules.kinds)) {
    openers.add(kind.opens.verb);
    for (const t of kind.transitions) rows.push(t);
  }

  it('every opening verb lands in the new register', () => {
    expect(openers.size).toBeGreaterThan(0);
    for (const verb of openers) expect(actRegister(verb), verb).toBe('new');
  });

  it('every non-system verb in the rules file has a register', () => {
    for (const row of rows) {
      if (row.who === 'system') continue;
      expect(actRegister(row.verb), row.verb).not.toBeNull();
    }
  });

  it('every system verb has none, so it can only be a system line', () => {
    for (const row of rows) {
      if (row.who !== 'system') continue;
      expect(actRegister(row.verb), row.verb).toBeNull();
    }
    expect(actRegister('confirm')).toBeNull();
  });

  it('the register is the register of the state the step lands in', () => {
    const byState: Record<string, ActRegister> = {
      open: 'new', offered: 'new',
      assigned: 'inProgress', under_review: 'inProgress',
      completed: 'endedWell', accepted: 'endedWell',
      failed: 'didNotEndWell', forfeited: 'didNotEndWell',
      cancelled: 'didNotEndWell', declined: 'didNotEndWell',
    };
    for (const row of rows) {
      if (row.who === 'system') continue;
      // An additive step — one that lands where it started — is in-progress
      // whatever state it sits in.
      const additive = Array.isArray(row.from) ? row.from.includes(row.to) : row.from === row.to;
      const want = additive ? 'inProgress' : byState[row.to];
      expect(want, `no register for state ${row.to}`).toBeDefined();
      expect(actRegister(row.verb), row.verb).toBe(want);
    }
  });

  it('the two additive verbs are in-progress rather than the register of where they sit', () => {
    expect(actRegister('bid')).toBe('inProgress');
    expect(actRegister('progress')).toBe('inProgress');
  });

  it('a verb nobody has taught it falls to the neutral end', () => {
    expect(actRegister('escalate')).toBe('neutralEnd');
    expect(actRegister('')).toBe('neutralEnd');
  });
});

describe('the role table against the rules file', () => {
  it("every non-system row's who is the role its verb reports", () => {
    for (const kind of Object.values(rules.kinds)) {
      expect(actWhoRole(kind.opens.verb), kind.opens.verb).toBe('opener');
      for (const t of kind.transitions) {
        if (t.who === 'system') {
          expect(actWhoRole(t.verb), t.verb).toBeNull();
          continue;
        }
        expect(actWhoRole(t.verb), t.verb).toBe(t.who);
      }
    }
  });

  it('every role the rules file uses has a sentence in the copy file', () => {
    const copy = JSON.parse(readFileSync(canonicalPath, 'utf8'));
    const roles = new Set<string>(['opener']);
    for (const kind of Object.values(rules.kinds)) {
      for (const t of kind.transitions) if (t.who !== 'system') roles.add(t.who);
    }
    for (const role of roles) {
      expect(copy.seal_panel.sentences[role], role).toBeTruthy();
    }
  });
});
