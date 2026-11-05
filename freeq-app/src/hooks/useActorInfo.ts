import { useState, useEffect } from 'react';

/** The server's `/api/v1/actors/{id}` answer, as far as the app reads it. */
export interface ActorInfo {
  actor_class?: string;
  did?: string;
  online?: boolean;
  spawned?: boolean;
  parent_did?: string;
  parent_nick?: string;
  channel?: string;
  capabilities?: string[];
  ttl?: number;
  task?: string;
  provenance?: {
    creator_did?: string;
    /** Set by the server when it proved the claim. */
    _verified?: boolean;
    source_repo?: string;
    implementation_ref?: string;
    revocation_authority?: string;
    origin_type?: string;
    authority_basis?: string;
  };
  presence?: {
    state?: string;
    status?: string;
    task?: string;
  };
}

/**
 * Ask the server what it knows about an actor (agent class, provenance,
 * presence): by DID first, then by nick (a spawned agent may have no DID
 * yet), skipping the nick when there is none. Asks again when `refreshKey`
 * changes. An answer to a request that a newer one has replaced, or that
 * lands after unmount, is dropped; the last answer stays while a new
 * request is out.
 */
export function useActorInfo(
  did: string | undefined,
  nick: string | undefined,
  refreshKey: string,
): ActorInfo | null {
  const [info, setInfo] = useState<ActorInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchActor = async () => {
      if (did) {
        const r = await fetch(`/api/v1/actors/${encodeURIComponent(did)}`);
        if (r.ok) {
          const body = await r.json();
          if (!cancelled) setInfo(body);
          return;
        }
      }
      if (!nick || cancelled) return;
      const r2 = await fetch(`/api/v1/actors/${encodeURIComponent(nick)}`);
      if (r2.ok) {
        const body = await r2.json();
        if (!cancelled) setInfo(body);
      }
    };
    fetchActor().catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [did, nick, refreshKey]);

  return info;
}
