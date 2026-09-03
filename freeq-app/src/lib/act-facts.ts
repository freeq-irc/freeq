/**
 * The facts grid: an act card labels the machine fields it understands,
 * instead of listing them raw — audience, money, deadlines, capabilities, the
 * note, the context link and its hash, and the payment and revision fields.
 * The labels live in `spec/act-card-copy.json` beside the rest of the card's
 * words; the card body is the title and this one grid, so no value is ever
 * drawn without its key. A field with no label here still draws, under its own
 * key (see `unknownFields`), so nothing signed is ever invisible.
 */
import copySpec from './act-card-copy.json';

const F: Record<string, string> = (copySpec as any).facts;

/** Resolves a DID (or nick) to what a reader should see. Injected so this
 *  module stays pure; callers pass the app's display resolver. */
export type NameResolver = (key: string) => string;

/** Unix-seconds string → a short local time a fact can carry. */
function factTime(unixSeconds: string): string | null {
  const n = Number(unixSeconds);
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n * 1000).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

/**
 * The labelled facts for one event, in a fixed order: audience, money,
 * deadlines, capabilities, then the note, the context link and its hash, then
 * pay to, payment, replaces and scope. `isOpener` is whether this event
 * created the action (only an opener is "offered to: anyone" — a follow-up's
 * missing act-to means nothing).
 */
export function actFacts(
  fields: Record<string, string>,
  isOpener: boolean,
  resolve: NameResolver,
  winnerDid?: string,
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const to = fields['act-to'];
  if (to) out.push([F.offered_to, resolve(to)]);
  else if (isOpener) out.push([F.offered_to, F.anyone]);
  if (winnerDid) out.push([F.awarded_to, resolve(winnerDid)]);
  if (fields['act-price']) out.push([F.price, fields['act-price']]);
  if (fields['act-bid']) out.push([F.bid, fields['act-bid']]);
  const dl = fields['act-deadline'] && factTime(fields['act-deadline']);
  if (dl) out.push([F.deadline, dl]);
  const bdl = fields['act-bid-deadline'] && factTime(fields['act-bid-deadline']);
  if (bdl) out.push([F.bid_deadline, bdl]);
  if (fields['act-caps']) out.push([F.caps, fields['act-caps']]);
  if (fields['act-note']) out.push([F.note, fields['act-note']]);
  if (fields['act-ctx']) out.push([F.ctx, fields['act-ctx']]);
  // The hash is what the signature covers, so it rides along for anyone
  // checking the bytes they fetched.
  if (fields['act-ctx-h']) out.push([F.ctx_h, fields['act-ctx-h']]);
  // `act-pay-to` may be a DID or a plain payment address, so only a DID goes
  // through the resolver; anything else is shown exactly as it was sent.
  const payTo = fields['act-pay-to'];
  if (payTo) out.push([F.pay_to, payTo.startsWith('did:') ? resolve(payTo) : payTo]);
  if (fields['act-tx']) out.push([F.tx, fields['act-tx']]);
  if (fields['act-replaces']) out.push([F.replaces, fields['act-replaces']]);
  if (fields['act-scope']) out.push([F.scope, fields['act-scope']]);
  return out;
}

/** The label the context row carries, so a renderer can draw that one value as
 *  a link without holding the word itself. */
export const ctxLabel: string = F.ctx;

/** The `act-*` fields the card already speaks or consumes structurally.
 *  Everything else draws under its own key. */
const KNOWN = new Set([
  'act', 'act-verb', 'act-id', 'act-title', 'act-to', 'act-note', 'act-ctx', 'act-ctx-h',
  'act-deadline', 'act-bid-deadline', 'act-caps', 'act-price', 'act-bid',
  'act-accepts', 'act-subject', 'act-pay-to', 'act-tx', 'act-replaces', 'act-scope',
]);

/** Fields the card has no label for, under their raw keys — the unknown-verb
 *  law's sibling. */
export function unknownFields(fields: Record<string, string>): Array<[string, string]> {
  return Object.entries(fields)
    .filter(([k]) => k.startsWith('act-') && !KNOWN.has(k))
    .map(([k, v]) => [k.replace(/^act-/, ''), v]);
}
