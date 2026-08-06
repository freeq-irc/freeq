/**
 * Learning who a DM is addressed to, before the first message goes out.
 *
 * A DM's wire target is a nick until something teaches us the peer's DID —
 * a shared channel's member list, or a WHOIS. Nothing does either for a
 * stranger, so a first DM used to leave addressed to a bare nick, and a bare
 * nick is not a venue any verifier can rebuild: the SDK signs nothing it
 * cannot name a venue for, so the very first thing said to someone new was
 * also the one message with no evidence of who wrote it.
 *
 * The fix is to resolve before sending rather than to sign a guess.
 */

/** What the gate needs to know about peers — the SDK, in practice. */
export interface DmPeerLookup {
  /** The peer's DID if it is already known, addressing-grade. */
  didForNick(nick: string): string | undefined;
  /** Fire a WHOIS and settle when the reply is in (or the wait expires). */
  requestWhois(nick: string): Promise<unknown>;
}

/**
 * The thread a DM belongs to: the peer's DID once we know it, else the nick.
 *
 * The SDK addresses and echoes a DM under exactly this key, so a local buffer
 * filed anywhere else is a second thread with the same person in it — and the
 * message the user just sent appears to have gone nowhere.
 */
export function dmThreadKey(
  target: string,
  didForNick: (nick: string) => string | undefined,
): string {
  if (target.startsWith('#') || target.startsWith('&') || target.startsWith('did:')) {
    return target;
  }
  return didForNick(target) ?? target;
}

/**
 * Build the gate every DM send passes through.
 *
 * Channels, DIDs and peers we can already name go straight out, synchronously
 * — the common case pays nothing. An unknown nick is probed once per session
 * and its sends queue behind that one probe, so messages keep the order they
 * were typed in. A peer who never answers (a guest has no DID to learn) is not
 * probed again, and their messages go out addressed to the nick and unsigned:
 * unsigned is honest, and waiting forever would be worse.
 */
export function createDmSendGate(
  peers: DmPeerLookup,
): (target: string, send: () => void) => void {
  const probed = new Map<string, Promise<unknown>>();

  return (target: string, send: () => void) => {
    const isChannel = target.startsWith('#') || target.startsWith('&');
    if (isChannel || target.startsWith('did:')) {
      send();
      return;
    }
    const key = target.toLowerCase();
    const pending = probed.get(key);
    if (pending) {
      // Queue behind whatever is already in flight for this peer, so a second
      // message can't overtake the first while it waits.
      probed.set(key, pending.then(send, send));
      return;
    }
    if (peers.didForNick(target)) {
      send();
      return;
    }
    probed.set(
      key,
      peers.requestWhois(target).then(send, send),
    );
  };
}
