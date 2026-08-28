/**
 * Peer discovery for @freeq/pi.
 *
 * WHY NOT PRESENCE: freeq relays PRESENCE to peers over the IRC `AWAY`
 * back-compat mechanism, and "back from away" is parameterless by IRC
 * semantics — so the server drops the status string for `online`/`active`/
 * `idle` states (freeq-server connection/mod.rs, `is_clear` branch). An
 * *active* agent therefore cannot advertise session metadata through
 * presence at all. Verified empirically in the M1 harness: peers appeared
 * with `no metadata`.
 *
 * So discovery is an application-level announcement over the existing
 * `+freeq.at/event=*` coordination-event channel (TAGMSG), which the SDK
 * already parses, de-dupes by event id, and annotates with the sender's DID.
 * No server change required, and it carries structured JSON rather than a
 * squeezed status line.
 *
 * Protocol (v1):
 *   hello      — "I'm here, here's my metadata"; sent on join and on demand
 *   hello_ack  — reply to a hello, so the newcomer learns about incumbents
 *
 * Ack storms are avoided by replying only to `hello`, never to `hello_ack`.
 *
 * SECURITY: the DID inside a hello payload is self-asserted and MUST NOT be
 * used for authorization. Tier decisions use the server-backed
 * `resolveSenderDid()` only (see connection.ts / M2 pipeline).
 */

import type { SessionMeta } from "./presence.js";

export const PI_HELLO = "pi_hello";
export const PI_HELLO_ACK = "pi_hello_ack";
export const PI_PROTOCOL_VERSION = 1;

/** Wire payload of a hello / hello_ack. */
export interface HelloPayload {
  v: number;
  /** Advertised session metadata (never contains paths — see presence.ts). */
  meta: SessionMeta;
  /** Self-asserted DID. Informational only; never used for authorization. */
  did?: string;
  /** Agent software, for future compatibility shims. */
  agent: string;
}

export function buildHello(meta: SessionMeta, did: string | undefined): HelloPayload {
  return { v: PI_PROTOCOL_VERSION, meta, did, agent: "pi" };
}

/** Parse and validate an inbound hello payload. Returns undefined if invalid. */
export function parseHello(raw: unknown): HelloPayload | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.v !== "number" || o.v < 1) return undefined;

  const meta: SessionMeta = {};
  if (o.meta && typeof o.meta === "object") {
    for (const [k, v] of Object.entries(o.meta as Record<string, unknown>)) {
      if (typeof v !== "string") continue;
      if (k === "session" || k === "project" || k === "repo" || k === "branch" || k === "model") {
        // Cap length: a peer must not be able to blow up our TUI with a
        // megabyte "branch" name.
        meta[k] = v.slice(0, 120);
      }
    }
  }
  return {
    v: o.v,
    meta,
    did: typeof o.did === "string" ? o.did.slice(0, 200) : undefined,
    agent: typeof o.agent === "string" ? o.agent.slice(0, 40) : "unknown",
  };
}

/** Tags for an outbound coordination event carrying a hello. */
export function helloTags(eventType: string, payload: HelloPayload): Record<string, string> {
  return {
    "+freeq.at/event": eventType,
    "+freeq.at/payload": encodeURIComponent(JSON.stringify(payload)),
  };
}
