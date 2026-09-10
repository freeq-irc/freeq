/**
 * Identity records: what a person publishes in their own repository about
 * which signing keys and which bots are theirs.
 *
 * Two record types, both public entries in the account's AT Protocol
 * repository: `at.freeq.deviceKey` announces a signing key a device holds,
 * or retires one; `at.freeq.agentKey` announces a bot the account claims as
 * its own, or retires that claim. The PDS writes them into a signed commit;
 * that part happens elsewhere.
 *
 * The Rust SDK owns the contract. `spec/identity-record-vectors.json` is the
 * shared file, and `identity-records.vectors.test.ts` holds this side to it.
 */
import { type DidKey, decodeMultibaseEd25519, verifyEd25519 } from './did-key.js';
import { canonicalize, deriveKid } from './signing.js';

/** Record type for a signing key a device publishes, and for retiring one. */
export const DEVICE_KEY_TYPE = 'at.freeq.deviceKey';

/** Record type for a bot an account claims as its own, and for retiring one. */
export const AGENT_KEY_TYPE = 'at.freeq.agentKey';

/**
 * An `at.freeq.deviceKey` entry: either a key the account publishes
 * (`publicKeyMultibase`) or a retirement of one (`revokes`), never both.
 */
export interface DeviceKeyRecord {
  $type: string;
  did: string;
  publicKeyMultibase?: string;
  revokes?: string;
  /** The key id of the key that signed this entry. */
  kid: string;
  createdAt: string;
  label?: string;
  bindingSig: string;
}

/**
 * An `at.freeq.agentKey` entry: either a bot the account claims (`agentDid`)
 * or a retirement of that claim (`revokes`), never both.
 */
export interface AgentKeyRecord {
  $type: string;
  did: string;
  agentDid?: string;
  revokes?: string;
  /** The key id of the owner's device key that signed this entry. */
  kid: string;
  createdAt: string;
  label?: string;
  bindingSig: string;
}

/** A device key live at the instant asked about, and the record it came from. */
export interface LiveDeviceKey {
  kid: string;
  publicKeyMultibase: string;
  createdAt: Date;
  record: unknown;
}

/** A bot the account claims at that instant, and the record it came from. */
export interface LiveAgentLink {
  agentDid: string;
  kid: string;
  createdAt: Date;
  record: unknown;
}

const encoder = new TextEncoder();

// ─── the signed bytes ───────────────────────────────────────────────────

/**
 * The bytes a record signs: its JCS (RFC 8785) canonical form with the
 * `bindingSig` field removed. Takes the record either way — a record being
 * built has no signature yet, one read off the wire has one.
 *
 * Verifiers pass the object exactly as received, never a rebuilt copy, so
 * any field that changed in transit fails the signature.
 */
export function recordSignedBytes(record: object): Uint8Array {
  const { bindingSig: _omit, ...unsigned } = record as Record<string, unknown>;
  return encoder.encode(canonicalize(unsigned));
}

// ─── the builders ───────────────────────────────────────────────────────

/** Announce `key` as a signing key of `did`. */
export async function buildDeviceRecord(
  key: DidKey,
  did: string,
  createdAt: string,
  label?: string,
): Promise<DeviceKeyRecord> {
  const unsigned = {
    $type: DEVICE_KEY_TYPE,
    did,
    publicKeyMultibase: key.publicKeyMultibase,
    kid: await kidOf(key),
    createdAt,
    ...(label === undefined ? {} : { label }),
  };
  return { ...unsigned, bindingSig: await key.signer(recordSignedBytes(unsigned)) };
}

/**
 * Retire the device key named by `revokesKid`, signing with `signer` — the
 * retired key itself, or any other key of the same account.
 */
export async function buildDeviceRetirement(
  signer: DidKey,
  did: string,
  revokesKid: string,
  createdAt: string,
): Promise<DeviceKeyRecord> {
  const unsigned = {
    $type: DEVICE_KEY_TYPE,
    did,
    revokes: revokesKid,
    kid: await kidOf(signer),
    createdAt,
  };
  return { ...unsigned, bindingSig: await signer.signer(recordSignedBytes(unsigned)) };
}

/** Claim `agentDid` as a bot of `ownerDid`, signed by one of its keys. */
export async function buildAgentRecord(
  ownerKey: DidKey,
  ownerDid: string,
  agentDid: string,
  createdAt: string,
  label?: string,
): Promise<AgentKeyRecord> {
  const unsigned = {
    $type: AGENT_KEY_TYPE,
    did: ownerDid,
    agentDid,
    kid: await kidOf(ownerKey),
    createdAt,
    ...(label === undefined ? {} : { label }),
  };
  return { ...unsigned, bindingSig: await ownerKey.signer(recordSignedBytes(unsigned)) };
}

/** Withdraw the claim on `agentDid`. */
export async function buildAgentRetirement(
  ownerKey: DidKey,
  ownerDid: string,
  agentDid: string,
  createdAt: string,
): Promise<AgentKeyRecord> {
  const unsigned = {
    $type: AGENT_KEY_TYPE,
    did: ownerDid,
    revokes: agentDid,
    kid: await kidOf(ownerKey),
    createdAt,
  };
  return { ...unsigned, bindingSig: await ownerKey.signer(recordSignedBytes(unsigned)) };
}

async function kidOf(key: DidKey): Promise<string> {
  return deriveKid(decodeMultibaseEd25519(key.publicKeyMultibase));
}

// ─── the folds ──────────────────────────────────────────────────────────

/** A checked device key record, with the retirement that ended it. */
interface Candidate {
  kid: string;
  publicKeyMultibase: string;
  publicKey: Uint8Array;
  createdAt: number;
  retiredAt: number | null;
  record: unknown;
}

/** A checked agent claim, with the retirement that ended it. */
interface LinkCandidate {
  agentDid: string;
  kid: string;
  createdAt: number;
  retiredAt: number | null;
  record: unknown;
}

/**
 * The device keys of `did` live at `at`, earliest first.
 *
 * Records arrive as JSON because they come off the wire that way, and one
 * malformed entry must be dropped rather than fail the whole read.
 */
export async function foldDeviceRecords(
  did: string,
  records: unknown[],
  at: Date,
): Promise<LiveDeviceKey[]> {
  const when = at.getTime();
  return (await deviceState(did, records))
    .filter((k) => k.createdAt <= when && (k.retiredAt === null || k.retiredAt > when))
    .map((k) => ({
      kid: k.kid,
      publicKeyMultibase: k.publicKeyMultibase,
      createdAt: new Date(k.createdAt),
      record: k.record,
    }));
}

/**
 * The bots `did` claims at `at`, earliest first. A claim counts only if the
 * owner key that signed it was itself live under the device fold when the
 * claim was written.
 */
export async function foldAgentRecords(
  did: string,
  deviceRecords: unknown[],
  agentRecords: unknown[],
  at: Date,
): Promise<LiveAgentLink[]> {
  const devices = await deviceState(did, deviceRecords);
  const links: LinkCandidate[] = [];
  const retirements: { record: ParsedRecord; createdAt: number; value: unknown }[] = [];

  for (const value of agentRecords) {
    const record = parseRecord(value, AGENT_KEY_TYPE, did, ['agentDid', 'revokes', 'label']);
    if (!record) continue;
    const createdAt = parseInstant(record.createdAt);
    if (createdAt === null) continue;
    if (record.agentDid !== undefined && record.revokes === undefined) {
      const signer = signerLiveAt(devices, record.kid, createdAt);
      if (!signer) continue;
      const message = recordSignedBytes(value as object);
      if (!(await verifyEd25519(signer, message, record.bindingSig))) continue;
      links.push({
        agentDid: record.agentDid,
        kid: record.kid,
        createdAt,
        retiredAt: null,
        record: value,
      });
    } else if (record.agentDid === undefined && record.revokes !== undefined) {
      retirements.push({ record, createdAt, value });
    }
  }

  // One entry per bot: the earliest claim wins, so re-claiming a bot cannot
  // move the date a retirement is measured against.
  links.sort((a, b) => compare(a.agentDid, b.agentDid) || a.createdAt - b.createdAt);
  const unique = firstOfEach(links, (l) => l.agentDid);

  retirements.sort(
    (a, b) => a.createdAt - b.createdAt || compare(a.record.bindingSig, b.record.bindingSig),
  );
  for (const { record, createdAt, value } of retirements) {
    const revokes = record.revokes!;
    const target = unique.find((l) => l.agentDid === revokes);
    if (!target || createdAt <= target.createdAt) continue;
    const signer = signerLiveAt(devices, record.kid, createdAt);
    if (!signer) continue;
    const message = recordSignedBytes(value as object);
    if (!(await verifyEd25519(signer, message, record.bindingSig))) continue;
    if (target.retiredAt === null || target.retiredAt > createdAt) target.retiredAt = createdAt;
  }

  const when = at.getTime();
  unique.sort((a, b) => a.createdAt - b.createdAt || compare(a.agentDid, b.agentDid));
  return unique
    .filter((l) => l.createdAt <= when && (l.retiredAt === null || l.retiredAt > when))
    .map((l) => ({
      agentDid: l.agentDid,
      kid: l.kid,
      createdAt: new Date(l.createdAt),
      record: l.record,
    }));
}

/**
 * Every device key record of one account, checked, each carrying the
 * retirement that ended it. Both folds read the account's key history from
 * here, so they cannot disagree about who was live when.
 */
async function deviceState(did: string, records: unknown[]): Promise<Candidate[]> {
  const keys: Candidate[] = [];
  const retirements: { record: ParsedRecord; createdAt: number; value: unknown }[] = [];

  for (const value of records) {
    const record = parseRecord(value, DEVICE_KEY_TYPE, did, [
      'publicKeyMultibase',
      'revokes',
      'label',
    ]);
    if (!record) continue;
    const createdAt = parseInstant(record.createdAt);
    if (createdAt === null) continue;
    if (record.publicKeyMultibase !== undefined && record.revokes === undefined) {
      let publicKey: Uint8Array;
      try {
        publicKey = decodeMultibaseEd25519(record.publicKeyMultibase);
      } catch {
        continue;
      }
      // The record signs itself with its own key, so a wrong kid is signed
      // too: it is checked against the key it names.
      if (record.kid !== (await deriveKid(publicKey))) continue;
      const message = recordSignedBytes(value as object);
      if (!(await verifyEd25519(publicKey, message, record.bindingSig))) continue;
      keys.push({
        kid: record.kid,
        publicKeyMultibase: record.publicKeyMultibase,
        publicKey,
        createdAt,
        retiredAt: null,
        record: value,
      });
    } else if (record.publicKeyMultibase === undefined && record.revokes !== undefined) {
      retirements.push({ record, createdAt, value });
    }
  }

  // One entry per key id: the earliest record wins, so republishing a key
  // cannot revive it or move the date a retirement is measured against.
  keys.sort((a, b) => compare(a.kid, b.kid) || a.createdAt - b.createdAt);
  const unique = firstOfEach(keys, (k) => k.kid);

  // Retirements take effect in date order, because whether one counts turns
  // on its signer still being live when it was written. Retirements sharing
  // an instant are ordered by their signature so every implementation agrees.
  retirements.sort(
    (a, b) => a.createdAt - b.createdAt || compare(a.record.bindingSig, b.record.bindingSig),
  );
  for (const { record, createdAt, value } of retirements) {
    const revokes = record.revokes!;
    const target = unique.find((k) => k.kid === revokes);
    if (!target || createdAt <= target.createdAt) continue;
    const signer = unique.find((k) => k.kid === record.kid);
    if (!signer || signer.createdAt > createdAt) continue;
    // A key counts as live for signing its own retirement.
    if (signer !== target && signer.retiredAt !== null && signer.retiredAt <= createdAt) continue;
    const message = recordSignedBytes(value as object);
    if (!(await verifyEd25519(signer.publicKey, message, record.bindingSig))) continue;
    if (target.retiredAt === null || target.retiredAt > createdAt) target.retiredAt = createdAt;
  }

  unique.sort((a, b) => a.createdAt - b.createdAt || compare(a.kid, b.kid));
  return unique;
}

/** The public key of `kid`, if that key of the account was live at `when`. */
function signerLiveAt(
  devices: Candidate[],
  kid: string,
  when: number,
): Uint8Array | undefined {
  const key = devices.find((d) => d.kid === kid);
  if (!key || key.createdAt > when) return undefined;
  if (key.retiredAt !== null && key.retiredAt <= when) return undefined;
  return key.publicKey;
}

/** A record read off the wire: every field named by its type, or absent. */
interface ParsedRecord {
  did: string;
  kid: string;
  createdAt: string;
  bindingSig: string;
  publicKeyMultibase?: string;
  agentDid?: string;
  revokes?: string;
  label?: string;
}

/**
 * Read a JSON value as a record of `type` belonging to `did`, or null. Only
 * the fields that type declares are examined, so an unrelated extra field is
 * ignored rather than fatal — the Rust side reads them the same way.
 */
function parseRecord(
  value: unknown,
  type: string,
  did: string,
  optional: string[],
): ParsedRecord | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  for (const field of ['$type', 'did', 'kid', 'createdAt', 'bindingSig']) {
    if (typeof raw[field] !== 'string') return null;
  }
  if (raw.$type !== type || raw.did !== did) return null;
  const parsed: ParsedRecord = {
    did: raw.did as string,
    kid: raw.kid as string,
    createdAt: raw.createdAt as string,
    bindingSig: raw.bindingSig as string,
  };
  const named: Record<string, string> = {};
  for (const field of optional) {
    const present = raw[field];
    // null reads as absent, the way an absent Option does on the Rust side.
    if (present === undefined || present === null) continue;
    if (typeof present !== 'string') return null;
    named[field] = present;
  }
  return { ...parsed, ...named };
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$/;

/**
 * RFC 3339 only, keeping the dates the Rust side keeps and no others.
 *
 * Date.parse on its own rolls a day past the end of its month into the next
 * month and accepts hour 24, both of which chrono refuses, so the fields are
 * checked before the instant is taken. The one remaining difference is a
 * leap second (`:60`), which chrono accepts and this discards.
 */
function parseInstant(text: string): number | null {
  const parts = RFC3339.exec(text);
  if (!parts) return null;
  const field = (index: number): number => Number(parts[index] ?? '0');
  const [year, month, day] = [field(1), field(2), field(3)];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return null;
  if (field(4) > 23 || field(5) > 59 || field(6) > 59) return null;
  if (field(7) > 23 || field(8) > 59) return null;
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  }
  return [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]!;
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Keep the first entry of each key in an already-sorted list. */
function firstOfEach<T>(sorted: T[], keyOf: (item: T) => string): T[] {
  const out: T[] = [];
  for (const item of sorted) {
    if (out.length === 0 || keyOf(out[out.length - 1]!) !== keyOf(item)) out.push(item);
  }
  return out;
}
