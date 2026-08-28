/**
 * What a client can honestly say about who someone is.
 *
 * One rule, owned by the SDKs, rendered everywhere. The clients used to carry
 * their own copies of this logic and their own caches feeding it, and the same
 * sender read differently on different clients from identical bytes. This
 * module and the Rust SDK's `identity_claim` are the only two implementations,
 * and both replay the vectors in `spec/identity-claims.json`, so they cannot
 * drift apart silently. Clients render what they are handed and may append
 * only platform affordance suffixes.
 *
 * Two questions, never mixed on one surface:
 *
 * - A message row answers: who was the sender when this was sent. The row's
 *   own tags come first; the live room second; a stored cache never.
 * - A person surface answers: who is this person now. The live binding comes
 *   first, then the WHOIS lookup state machine.
 *
 * The states, the precedence, and every user-facing string come from
 * `spec/identity-claims.json`. The copy imported here (`./identity-claims.json`)
 * exists only because this package's build root cannot reach outside `src/`;
 * a test pins it byte-identical to the canonical file, so editing the canonical
 * without refreshing the copy is a failing suite, not silent drift.
 *
 * The one dated constant: rows older than the spec's `stamping_epoch` read
 * Unknown when they carry no account tag and their sender is absent — before
 * servers stamped tags, absence proves nothing, and absence has no format to
 * inspect the way a legacy signature does. The date lives in the spec file
 * and in no client.
 */

// `with { type: 'json' }` is not decoration: Node's ESM loader has required a
// type attribute on JSON imports since v22, so without it every consumer that
// runs this package as plain ESM (`node dist/index.js`) dies at import time
// with ERR_IMPORT_ATTRIBUTE_MISSING. Bundlers tolerated its absence, which is
// why it went unnoticed.
import spec from './identity-claims.json' with { type: 'json' };

export type IdentityClaimState =
  | 'atProtocol'
  | 'selfIssued'
  | 'relayed'
  | 'guest'
  | 'lookingUp'
  | 'unknown';

/** A finished claim: the state plus everything a surface needs to render it. */
export interface IdentityClaim {
  readonly state: IdentityClaimState;
  /** The DID the claim is about, when one is known. */
  readonly did: string | null;
  /** The relaying peer, when the claim came through one. */
  readonly origin: string | null;
  /** The short label above the line; null for the spinner state. */
  readonly label: string | null;
  /** The one-line explanation, fully rendered; null for the spinner state. */
  readonly line: string | null;
  /** The mark IS the claim, so it appears exactly where the claim holds. */
  readonly showsMark: boolean;
  /** Render motion, not words. */
  readonly isPending: boolean;
  /** The line names "the key below", so it needs a surface showing one. */
  readonly needsKeyCard: boolean;
}

/** Inputs for a message row. Tags come from the row itself; presence and the
 *  live binding come from the venue's roster — never from a stored cache. */
export interface MessageClaimInput {
  /** The row's `account` tag, if any. */
  account?: string | null;
  /** The row's `+freeq.at/origin` tag, if any. */
  origin?: string | null;
  /** Whether the sender's nick is in the venue's roster right now. */
  senderPresent?: boolean;
  /** The sender's live DID binding, only if present right now. */
  senderLiveDid?: string | null;
  /** The row's own timestamp (server `time` tag), unix seconds. */
  rowTimeUnix?: number | null;
}

/** What has been done about finding out who someone is. */
export type PersonLookup =
  | 'notAsked'
  | 'inFlight'
  | 'noAccount'
  | 'noSuchNick'
  | 'timedOut';

/** Inputs for a person surface. `seenOnlyViaPeer` and `binding` are mutually
 *  exclusive by construction: a first-hand binding means the person was seen
 *  here, not only through a peer. */
export interface PersonClaimInput {
  /** The live, first-hand DID binding, if one exists right now. */
  binding?: string | null;
  /** True when every sighting of this person came through a relaying peer.
   *  Such people are never WHOISed here — this server would answer about the
   *  wrong person. */
  seenOnlyViaPeer?: boolean;
  /** The relaying peer's name, when known. */
  viaPeerOrigin?: string | null;
  /** Whether their relayed messages carried an account. */
  viaPeerHadAccount?: boolean;
  /** The lookup state machine, for the case where nothing is on file. */
  lookup?: PersonLookup;
}

/** The claim for a message row: who was the sender when this was sent. */
export function claimForMessage(input: MessageClaimInput): IdentityClaim {
  const account = nonblank(input.account);
  const origin = nonblank(input.origin);
  // A relayed row splits on whether an account came with it: the origin
  // stamps one for every authenticated sender, so its absence is the origin
  // saying "guest". The lookup machinery never applies to relayed senders.
  if (origin) {
    return account
      ? render('relayed', account, origin)
      : render('guest', null, origin);
  }
  // The row's own tag beats the live room: a message row describes who sent
  // it then, not who holds the nick now.
  if (account) {
    return render(byDid(account), account, null);
  }
  // No tags. The live room may still answer — for rows that predate the tag
  // stampings while their author is standing right here.
  if (input.senderPresent) {
    const live = nonblank(input.senderLiveDid);
    return live ? render(byDid(live), live, null) : render('guest', null, null);
  }
  // No tags, absent sender. Tag absence is the guest answer only on rows
  // stored after servers stamped tags; before that it proves nothing, and a
  // row that cannot prove its age is treated the same way.
  const t = input.rowTimeUnix;
  if (typeof t === 'number' && t >= spec.stamping_epoch_unix) {
    return render('guest', null, null);
  }
  return render('unknown', null, null);
}

/** The claim for a person surface: who is this person now. */
export function claimForPerson(input: PersonClaimInput): IdentityClaim {
  if (input.seenOnlyViaPeer) {
    const origin = nonblank(input.viaPeerOrigin);
    return input.viaPeerHadAccount
      ? render('relayed', null, origin)
      : render('guest', null, origin ?? spec.states.relayed.origin_fallback);
  }
  const binding = nonblank(input.binding);
  if (binding) {
    return render(byDid(binding), binding, null);
  }
  switch (input.lookup ?? 'notAsked') {
    case 'inFlight':
      return render('lookingUp', null, null);
    case 'noAccount':
      return render('guest', null, null);
    default:
      return render('unknown', null, null);
  }
}

/** The claim for a person surface anchored to a message — a profile sheet or
 *  popover opened from a row. Live identity first, then the message's own
 *  evidence, then the lookup machine. Differs from `claimForMessage` in
 *  exactly one place: a live-known DID (`senderLiveDid` here means any DID
 *  known live — the roster, or a fresh WHOIS answer — not only a roster
 *  member) outranks the row's tag, because this surface answers who the
 *  person is NOW, where the row answers who sent it THEN. */
export function claimForSender(
  input: MessageClaimInput,
  lookup: PersonLookup = 'notAsked',
): IdentityClaim {
  if (nonblank(input.origin)) {
    // Relayed senders never go through the local lookup — a WHOIS to this
    // server about a relayed nick answers about the wrong person.
    return claimForMessage(input);
  }
  const live = nonblank(input.senderLiveDid);
  if (live) {
    return render(byDid(live), live, null);
  }
  const fromRow = claimForMessage({ ...input, senderLiveDid: null });
  // The row's evidence answered (a tag, or post-epoch absence). Only when it
  // could not — Unknown, the pre-epoch case — does the ask machinery decide.
  if (fromRow.state !== 'unknown') {
    return fromRow;
  }
  return claimForPerson({ lookup });
}

/** The epoch before which tag absence proves nothing, unix seconds. */
export function stampingEpochUnix(): number {
  return spec.stamping_epoch_unix;
}

function byDid(did: string): IdentityClaimState {
  return did.startsWith('did:key:') ? 'selfIssued' : 'atProtocol';
}

function nonblank(s: string | null | undefined): string | null {
  return s && s.trim() !== '' ? s : null;
}

function render(
  state: IdentityClaimState,
  did: string | null,
  origin: string | null,
): IdentityClaim {
  const s = spec.states;
  let label: string | null;
  let line: string | null;
  let flags: { shows_mark: boolean; is_pending: boolean; needs_key_card: boolean };
  switch (state) {
    case 'atProtocol':
      ({ label } = s.atProtocol);
      line = s.atProtocol.line;
      flags = s.atProtocol;
      break;
    case 'selfIssued':
      ({ label } = s.selfIssued);
      line = s.selfIssued.line;
      flags = s.selfIssued;
      break;
    case 'relayed': {
      const who = origin ?? s.relayed.origin_fallback;
      label = s.relayed.label;
      line = s.relayed.line.replaceAll('{origin}', who);
      flags = s.relayed;
      break;
    }
    case 'guest':
      label = s.guest.label;
      line = origin
        ? s.guest.line_relayed.replaceAll('{origin}', origin)
        : s.guest.line_local;
      flags = s.guest;
      break;
    case 'lookingUp':
      label = s.lookingUp.label;
      line = s.lookingUp.line;
      flags = s.lookingUp;
      break;
    case 'unknown':
      label = s.unknown.label;
      line = s.unknown.line;
      flags = s.unknown;
      break;
  }
  return {
    state,
    did,
    origin,
    label,
    line,
    showsMark: flags.shows_mark,
    isPending: flags.is_pending,
    needsKeyCard: flags.needs_key_card,
  };
}
