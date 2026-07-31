/**
 * Client-side chat signing: the document canonical, in TypeScript.
 *
 * This is the JS half of `freeq_sdk::chatsig` (Rust). The two MUST agree
 * byte-for-byte — a one-byte disagreement makes every signature from one look
 * like tampering to the other — so both are pinned to the shared vectors in
 * `spec/chat-signing-vectors.json`, which `signing.vectors.test.ts` replays.
 *
 * What gets signed, and why it changed: the old canonical was
 * `did\0target\0text\0timestamp`, where the timestamp was minted here and
 * never transmitted. The server re-minted its own, so a signature verified
 * only when both landed in the same second, and a *federated* receiver could
 * not rebuild the bytes at all. The document form fixes both: it signs over an
 * event id this client mints and sends (`+freeq.at/eventid`, which the server
 * adopts as the message's `msgid`), so any receiver — now or years later —
 * rebuilds exactly what was signed from the wire alone.
 */

/** The tag carrying the id the signer minted for this event. */
export const EVENT_ID_TAG = '+freeq.at/eventid';
/** The signature tag. Value is `ed25519:<kid>:<base64url sig>`. */
export const SIG_TAG = '+freeq.at/sig';

/**
 * The client-authored coordination tags a message document covers — a closed
 * set on purpose. "Every `+freeq.at/*` tag" would swallow tags the *server*
 * writes (reaction tallies, provenance, commit verdicts), and each new one
 * would invalidate signatures that were fine.
 */
export const COVERED_COORD_TAGS = ['event', 'payload', 'ref', 'task-id'] as const;

let signingKey: CryptoKeyPair | null = null;
let publicKeyB64: string | null = null;
let publicKeyKid: string | null = null;
let authenticatedDid: string | null = null;

/** Base64url encode (no padding). */
function b64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Lowercase hex of a byte array. */
function hex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/**
 * JCS (RFC 8785) canonicalization, for the shapes a chat document uses:
 * nested string maps only. Keys sort by code point, values are JSON strings —
 * which is what `JSON.stringify` already produces for the escaping rules
 * (`\"`, `\\`, `\b\f\n\r\t`, `\uXXXX` for other controls, raw UTF-8
 * otherwise), matching `serde_json` on the Rust side.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}

/** `sha256:<lowercase hex>` over the UTF-8 bytes of a wire body. */
export async function bodyHash(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  return `sha256:${hex(new Uint8Array(digest))}`;
}

/**
 * The venue of a channel event: the channel name, lowercased.
 *
 * Not cosmetic — the server folds a channel target before anything else sees
 * it, so signing the case the user typed would fail at the sender's own
 * origin.
 */
export function channelVenue(channel: string): string {
  return channel.toLowerCase();
}

/**
 * The venue of a direct message: `dm:<did_a>,<did_b>`, DIDs sorted.
 *
 * A DM's wire target is a nick (mutable, unique only per server) or a `did:`,
 * and history is replayed under whichever the *reader* asked for — so the wire
 * target is not something a verifier can reproduce. The sorted pair is, and
 * it's already the key the conversation is stored under.
 */
export function dmVenue(didA: string, didB: string): string {
  return didA <= didB ? `dm:${didA},${didB}` : `dm:${didB},${didA}`;
}

/**
 * The venue to sign for a wire target, or `null` for a bare nick: a nick is
 * not a venue, and the DM venue needs the peer's DID. Send unsigned rather
 * than sign a venue no verifier would rebuild.
 */
export function venueForTarget(target: string, senderDid: string): string | null {
  if (target.startsWith('#') || target.startsWith('&')) return channelVenue(target);
  if (target.startsWith('did:')) return dmVenue(senderDid, target);
  return null;
}

/** Crockford base32 alphabet, as ULIDs use it. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Mint an event id: a ULID — 48-bit millisecond timestamp then 80 random bits,
 * 26 uppercase Crockford base32 characters.
 *
 * The server checks the shape and that the embedded time is near its own
 * before adopting one, so the timestamp has to be real.
 */
export function newEventId(): string {
  let ms = Date.now();
  let out = '';
  for (let i = 0; i < 10; i++) {
    out = CROCKFORD[ms % 32] + out;
    ms = Math.floor(ms / 32);
  }
  const rand = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 0; i < 16; i++) out += CROCKFORD[rand[i]! % 32];
  return out;
}

/** Strip the client-tag vendor prefix from a tag name, if present. */
function strippedName(name: string): string {
  if (name.startsWith('+freeq.at/')) return name.slice('+freeq.at/'.length);
  if (name.startsWith('freeq.at/')) return name.slice('freeq.at/'.length);
  return name;
}

/** The fields of a chat message that its signature covers. */
export interface MessageDocFields {
  from: string;
  msgid: string;
  target: string;
  /** The wire body — ciphertext under E2EE, assembled body for multiline. */
  body: string;
  /** Root msgid this replies to. */
  reply?: string;
  /** Root msgid this revises. */
  edit?: string;
  /** Tags to draw covered coordination values from (any spelling). */
  tags?: Record<string, string>;
}

/**
 * The exact UTF-8 string a message signature covers. Optional fields appear
 * only when present, so a plain message reduces to four keys.
 */
export async function messageCanonical(fields: MessageDocFields): Promise<string> {
  const doc: Record<string, unknown> = {
    body: await bodyHash(fields.body),
    from: fields.from,
    msgid: fields.msgid,
    target: fields.target,
  };
  if (fields.reply) doc.reply = fields.reply;
  if (fields.edit) doc.edit = fields.edit;
  const coord: Record<string, string> = {};
  for (const [name, value] of Object.entries(fields.tags ?? {})) {
    const key = strippedName(name);
    if ((COVERED_COORD_TAGS as readonly string[]).includes(key)) coord[key] = value;
  }
  if (Object.keys(coord).length > 0) doc.coord = coord;
  return canonicalize(doc);
}

/**
 * The exact UTF-8 string a mutation signature covers (delete / react /
 * unreact). `msgid` is this event's own id; `subject` is the root msgid of the
 * message it acts on.
 */
export function mutationCanonical(fields: {
  kind: 'delete' | 'react' | 'unreact';
  from: string;
  msgid: string;
  target: string;
  subject: string;
  emoji?: string;
}): string {
  const doc: Record<string, unknown> = {
    from: fields.from,
    kind: fields.kind,
    msgid: fields.msgid,
    subject: fields.subject,
    target: fields.target,
  };
  if (fields.emoji && fields.kind !== 'delete') doc.emoji = fields.emoji;
  return canonicalize(doc);
}

/** Derive a key id: base64url of the first 16 bytes of SHA-256 over the key. */
export async function deriveKid(rawPublicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', rawPublicKey as unknown as ArrayBuffer);
  return b64url(new Uint8Array(digest).slice(0, 16));
}

/** Generate an Ed25519 keypair and return its base64url public key. */
export async function generateSigningKey(): Promise<string | null> {
  try {
    const kp = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    signingKey = kp;
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    publicKeyB64 = b64url(rawPub);
    publicKeyKid = await deriveKid(rawPub);
    return publicKeyB64;
  } catch (e) {
    console.warn('Ed25519 not available in Web Crypto, falling back to server signing:', e);
    return null;
  }
}

/** Set the authenticated DID (called after SASL success). */
export function setSigningDid(did: string) {
  authenticatedDid = did;
}

/** A signed event: the id the signature covers, and the signature tag value. */
export interface SignedEvent {
  eventId: string;
  sigTag: string;
}

async function signCanonical(canonical: string): Promise<string | null> {
  if (!signingKey?.privateKey || !publicKeyKid) return null;
  try {
    const sig = await crypto.subtle.sign(
      'Ed25519',
      signingKey.privateKey,
      new TextEncoder().encode(canonical),
    );
    return `ed25519:${publicKeyKid}:${b64url(sig)}`;
  } catch {
    return null;
  }
}

/**
 * Sign an outgoing message. Returns the event id to send as
 * `+freeq.at/eventid` **and** the `+freeq.at/sig` value — both are needed,
 * because the signature covers the id.
 *
 * `null` when this session has no signing key, or when the venue can't be
 * determined (a bare-nick DM whose peer DID we haven't learned): unsigned is
 * honest, a signature over a guessed venue reads as tampering.
 */
export async function signMessage(
  target: string,
  body: string,
  opts: { reply?: string; edit?: string; tags?: Record<string, string> } = {},
): Promise<SignedEvent | null> {
  if (!signingKey?.privateKey || !authenticatedDid) return null;
  const venue = venueForTarget(target, authenticatedDid);
  if (!venue) return null;
  const eventId = newEventId();
  const canonical = await messageCanonical({
    from: authenticatedDid,
    msgid: eventId,
    target: venue,
    body,
    reply: opts.reply,
    edit: opts.edit,
    tags: opts.tags,
  });
  const sigTag = await signCanonical(canonical);
  return sigTag ? { eventId, sigTag } : null;
}

/**
 * Sign a mutation (delete / react / unreact). Durable state under a user's
 * name gets signed; ephemera (typing, AV signalling) don't.
 */
export async function signMutation(
  kind: 'delete' | 'react' | 'unreact',
  target: string,
  subject: string,
  emoji?: string,
): Promise<SignedEvent | null> {
  if (!signingKey?.privateKey || !authenticatedDid) return null;
  const venue = venueForTarget(target, authenticatedDid);
  if (!venue) return null;
  const eventId = newEventId();
  const canonical = mutationCanonical({
    kind,
    from: authenticatedDid,
    msgid: eventId,
    target: venue,
    subject,
    emoji,
  });
  const sigTag = await signCanonical(canonical);
  return sigTag ? { eventId, sigTag } : null;
}

/** Get the public key (for MSGSIG registration). */
export function getPublicKey(): string | null {
  return publicKeyB64;
}

/** The key id of this session's signing key, as signatures name it. */
export function getKid(): string | null {
  return publicKeyKid;
}

/** Reset signing state (on disconnect). */
export function resetSigning() {
  signingKey = null;
  publicKeyB64 = null;
  publicKeyKid = null;
  authenticatedDid = null;
}
