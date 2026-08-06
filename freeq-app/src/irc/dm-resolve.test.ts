/**
 * A first DM waits to learn who it is talking to.
 */
import { describe, it, expect, vi } from 'vitest';
import { createDmSendGate, dmThreadKey } from './dm-resolve';

/** A peer directory whose WHOIS answers are scripted per nick. */
function peers(dids: Record<string, string | undefined>) {
  const asked: string[] = [];
  const answers = new Map<string, { resolve: () => void; reject: () => void }>();
  return {
    asked,
    answers,
    lookup: {
      didForNick: (nick: string) => dids[nick.toLowerCase()],
      requestWhois: (nick: string) => {
        asked.push(nick);
        return new Promise<void>((resolve, reject) => {
          answers.set(nick.toLowerCase(), {
            // A WHOIS reply teaches the directory before it resolves, exactly
            // as the SDK caches numeric 330 before ending the WHOIS.
            resolve: () => {
              dids[nick.toLowerCase()] = `did:plc:${nick.toLowerCase()}`;
              resolve();
            },
            reject: () => reject(new Error('timed out')),
          });
        });
      },
    },
  };
}

describe('where a DM thread lives', () => {
  const known = (nick: string) => (nick.toLowerCase() === 'bob' ? 'did:plc:bob' : undefined);

  it('files under the peer DID once the peer is named', () => {
    expect(dmThreadKey('bob', known)).toBe('did:plc:bob');
    expect(dmThreadKey('BOB', known)).toBe('did:plc:bob');
  });

  it('stays on the nick while the peer is unnamed', () => {
    expect(dmThreadKey('stranger', known)).toBe('stranger');
  });

  it('leaves channels and DID targets alone', () => {
    expect(dmThreadKey('#room', known)).toBe('#room');
    expect(dmThreadKey('did:plc:carol', known)).toBe('did:plc:carol');
  });
});

describe('the gate in front of a DM send', () => {
  it('lets a channel message straight through', () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    let sent = false;
    gate('#room', () => (sent = true));
    expect(sent, 'a channel has nobody to resolve').toBe(true);
    expect(p.asked).toEqual([]);
  });

  it('lets a DM to a peer we can already name straight through', () => {
    const p = peers({ bob: 'did:plc:bob' });
    const gate = createDmSendGate(p.lookup);
    let sent = false;
    gate('bob', () => (sent = true));
    expect(sent).toBe(true);
    expect(p.asked, 'nothing to ask: we know who bob is').toEqual([]);
  });

  it('lets a DM already addressed by DID straight through', () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    let sent = false;
    gate('did:plc:carol', () => (sent = true));
    expect(sent).toBe(true);
    expect(p.asked).toEqual([]);
  });

  it('holds a first DM to an unknown nick until the peer is named', async () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    let sent = false;
    gate('dana', () => (sent = true));
    expect(sent, 'the send waits — sending now would go out unsigned').toBe(false);
    expect(p.asked).toEqual(['dana']);

    p.answers.get('dana')!.resolve();
    await vi.waitFor(() => expect(sent).toBe(true));
  });

  it('sends anyway when the peer never answers', async () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    let sent = false;
    gate('ghost', () => (sent = true));
    p.answers.get('ghost')!.reject();
    // A guest has no DID to learn. The message still goes out, addressed to
    // the nick and unsigned — waiting forever would be worse than unsigned.
    await vi.waitFor(() => expect(sent).toBe(true));
  });

  it('asks once per peer, however many messages follow', async () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    const sent: string[] = [];
    gate('erin', () => sent.push('first'));
    gate('erin', () => sent.push('second'));
    expect(p.asked, 'one probe, not one per message').toEqual(['erin']);

    p.answers.get('erin')!.resolve();
    await vi.waitFor(() => expect(sent).toHaveLength(2));
    expect(sent, 'messages keep the order they were typed in').toEqual(['first', 'second']);

    gate('erin', () => sent.push('third'));
    await vi.waitFor(() => expect(sent).toHaveLength(3));
    expect(p.asked, 'a peer is probed once per session, resolved or not').toEqual(['erin']);
  });

  it('does not re-probe a peer who never resolved', async () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    const sent: string[] = [];
    gate('ghost', () => sent.push('first'));
    p.answers.get('ghost')!.reject();
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    gate('ghost', () => sent.push('second'));
    await vi.waitFor(() => expect(sent).toHaveLength(2));
    expect(p.asked).toEqual(['ghost']);
  });

  it('treats a nick as one peer whatever case it is typed in', async () => {
    const p = peers({});
    const gate = createDmSendGate(p.lookup);
    const sent: string[] = [];
    gate('Frank', () => sent.push('first'));
    gate('frank', () => sent.push('second'));
    expect(p.asked).toEqual(['Frank']);
    p.answers.get('frank')!.resolve();
    await vi.waitFor(() => expect(sent).toHaveLength(2));
  });
});
