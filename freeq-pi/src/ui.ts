/**
 * What the terminal shows about freeq without being asked.
 *
 * Until now the extension used exactly two pi UI primitives, `notify` and
 * `confirm`: every fact about the connection scrolled past as a toast and was
 * gone. You could not glance at your terminal and see that you were online,
 * who was around, or that a handoff was waiting for you. This module renders
 * the persistent parts — footer status, the offer card, peer colours — from
 * plain data, so the extension owns the state and this file owns the look.
 *
 * Everything here is a pure function of its inputs, which is what makes it
 * testable without a TUI and keeps the extension's event handlers from
 * growing rendering code.
 */

import { createHash } from "node:crypto";

// ── Footer status ───────────────────────────────────────────────────────

export interface FooterState {
  online: boolean;
  passive?: boolean;
  nick?: string;
  channels: number;
  peers: number;
  offersWaiting: number;
  /** What the agent is doing, if anything: the work label. */
  working?: string;
  inCall?: string;
}

/**
 * One line, always visible. Densest facts first; the ones that change most
 * (offers, work) at the end where the eye lands last but returns to.
 *
 *   ⬡ freeq · chad-bot-freeq · 3 ch · 2 peers · 1 offer · ⚙ handoff: fix parser
 */
export function footerLine(s: FooterState): string {
  if (!s.online) {
    return s.passive ? "⬡ freeq · passive (another window holds this project)" : "⬡ freeq · offline";
  }
  const parts = [`⬡ freeq`, s.nick ?? "?", `${s.channels} ch`, `${s.peers} peer${s.peers === 1 ? "" : "s"}`];
  if (s.offersWaiting > 0) parts.push(`${s.offersWaiting} offer${s.offersWaiting === 1 ? "" : "s"} ⏳`);
  if (s.inCall) parts.push(`☎ ${s.inCall}`);
  if (s.working) parts.push(`⚙ ${s.working}`);
  return parts.join(" · ");
}

// ── Offer card ──────────────────────────────────────────────────────────

export interface OfferCardInput {
  taskId: string;
  title: string;
  from: string;
  tier: string;
  /** Epoch ms queued. */
  queuedAt: number;
  /** Epoch ms deadline, if any. */
  deadline?: number;
  brief?: string;
  now?: number;
}

/**
 * The card shown above the editor when work is waiting. Replaces a toast that
 * scrolled away: an offer is a thing to act on, so it stays until acted on.
 */
export function offerCardLines(o: OfferCardInput, width = 72): string[] {
  const now = o.now ?? Date.now();
  const age = formatAge(now - o.queuedAt);
  const due = o.deadline ? ` · due ${formatAge(o.deadline - now, true)}` : "";
  const id = o.taskId.slice(0, 10);
  // Header is `┌─ <label> ─…─┐`, padded so every row is exactly `width` wide.
  const label = "─ handoff offered ";
  const head = `┌${label}${"─".repeat(Math.max(0, width - 2 - [...label].length))}┐`;
  const rows: string[] = [
    head,
    `│ ${fit(o.title, width - 4)} │`,
    `│ ${fit(`from ${o.from} (${o.tier}) · ${age} ago${due} · ${id}`, width - 4)} │`,
  ];
  if (o.brief) {
    const firstLine = o.brief.split("\n").find((l) => l.trim()) ?? "";
    rows.push(`│ ${fit(firstLine.trim(), width - 4)} │`);
  }
  rows.push(`│ ${fit(`/freeq accept ${id}   ·   /freeq decline ${id} [reason]`, width - 4)} │`);
  rows.push(`└${"─".repeat(width - 2)}┘`);
  return rows;
}

// ── Peer colours ────────────────────────────────────────────────────────

/**
 * A stable colour per identity. Same DID, same colour, every session, every
 * machine — and the same choice the web client would make from the same
 * input, so a person is recognisable across surfaces.
 *
 * Returns an index into a small palette rather than a colour, so the caller
 * can map it onto whatever the active theme offers. Eight entries: enough to
 * tell a handful of peers apart, few enough that the colours stay distinct.
 */
export const PEER_PALETTE_SIZE = 8;

export function peerColorIndex(did: string): number {
  const h = createHash("sha256").update(did).digest();
  return h[0]! % PEER_PALETTE_SIZE;
}

// ── Peer roster ─────────────────────────────────────────────────────────

export interface RosterPeer {
  nick: string;
  did?: string;
  state?: string;
  working?: string;
  project?: string;
  model?: string;
  /** Epoch ms last seen. */
  seen: number;
  tier?: string;
}

/**
 * `/freeq peers` as a table rather than a paragraph. One row per peer, most
 * recently seen first, with what they are doing — the thing you actually
 * wanted to know.
 */
export function rosterLines(peers: RosterPeer[], now = Date.now()): string[] {
  if (peers.length === 0) return ["no peers in your channels — discovery needs a shared room"];
  const sorted = [...peers].sort((a, b) => b.seen - a.seen);
  const nickW = Math.min(24, Math.max(4, ...sorted.map((p) => p.nick.length)));
  const rows = sorted.map((p) => {
    const nick = p.nick.padEnd(nickW);
    const st = (p.state ?? "?").padEnd(9);
    const what = p.working ? `⚙ ${p.working}` : p.project ? `in ${p.project}` : "";
    const model = p.model ? ` · ${p.model}` : "";
    const tier = p.tier && p.tier !== "observe" ? ` · ${p.tier}` : "";
    return `${nick}  ${st}  ${what}${model}${tier}  ${formatAge(now - p.seen)} ago`;
  });
  return rows;
}

// ── helpers ─────────────────────────────────────────────────────────────

export function formatAge(ms: number, future = false): string {
  const s = Math.max(0, Math.round(Math.abs(ms) / 1000));
  const out =
    s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : s < 86400 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`;
  return future && ms < 0 ? `${out} overdue` : out;
}

function fit(s: string, w: number): string {
  const one = s.replace(/\s+/g, " ");
  if (one.length <= w) return one.padEnd(w);
  return `${one.slice(0, Math.max(0, w - 1))}…`;
}
