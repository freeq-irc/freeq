/**
 * Does a pre-key bundle belong to the DID it is published under?
 *
 * A steward seals a room key to a member's X25519 identity key, which it
 * reads from the member's pre-key bundle on the freeq host. The bundle is
 * only as trustworthy as the binding from it to the DID, so the host must not
 * be the one vouching for it:
 *
 * - `did:key`: `signing_key` must be the DID's own Ed25519 key, and
 *   `spk_signature` must verify over `signed_pre_key` with it.
 * - any other DID (`did:plc`, `did:web`): `signing_key` must be a device key
 *   the account published as an `at.freeq.deviceKey` record in its own
 *   repository — read from the DID's PDS and checked against the repository's
 *   signed commit, never from the freeq host — live (not retired, not
 *   expired), and `spk_signature` must verify over `signed_pre_key` with it.
 *
 * Anything else is refused, with a reason a steward can show. A refusal that
 * may pass later (the device key record not published yet, the PDS not
 * answering) carries `retry: true`.
 */
import { decodeMultibaseEd25519, verifyEd25519 } from './did-key.js';
import {
  DEVICE_KEY_TYPE,
  deviceKeyHistory,
  listRecordEntries,
  provenRecords,
  retiredOrExpired,
} from './identity-records.js';
import type { FoundKey, RecordReader } from './key-lookup.js';
import { deriveKid } from './signing.js';

/** Where a DID's published device keys are looked up: `PdsDeviceKeys`, or
 *  anything shaped like a `KeyLookup`. Only a key whose source is
 *  `IdentityRecord` binds a bundle. */
export interface DeviceKeySource {
  keyFor(did: string, kid: string): Promise<FoundKey | null>;
}

export type BindingResult = { ok: true } | { ok: false; reason: string; retry?: boolean };

/** The bundle fields the binding reads. Keys are base64 or base64url. */
export interface BindableBundle {
  signing_key?: string;
  spk_signature: string;
  signed_pre_key: string;
}

/**
 * Check that `bundle` belongs to `did`; see the module comment for the rule.
 * `spk`: the signed pre-key's bytes when the caller already decoded them.
 * `deviceKeys`: where a non-did:key DID's device keys are read; without it
 * such a bundle is refused.
 */
export async function verifyBundleBinding(
  did: string,
  bundle: BindableBundle,
  opts: { spk?: Uint8Array; deviceKeys?: DeviceKeySource; now?: Date } = {},
): Promise<BindingResult> {
  let spk: Uint8Array;
  try {
    spk = opts.spk ?? decodeB64(bundle.signed_pre_key);
  } catch {
    return { ok: false, reason: 'malformed pre-key bundle' };
  }
  if (typeof bundle.spk_signature !== 'string') return { ok: false, reason: 'malformed pre-key bundle' };

  if (did.startsWith('did:key:')) return bindDidKey(did, bundle, spk);

  if (!bundle.signing_key) {
    return { ok: false, reason: 'bundle has no signing_key; it cannot be bound to a device key the DID published' };
  }
  let signingKey: Uint8Array;
  let sigUrl: string;
  try {
    signingKey = decodeB64(bundle.signing_key);
  } catch {
    return { ok: false, reason: 'malformed signing_key' };
  }
  if (signingKey.length !== 32) return { ok: false, reason: 'malformed signing_key' };
  try {
    sigUrl = b64url(decodeB64(bundle.spk_signature));
  } catch {
    return { ok: false, reason: 'malformed spk_signature' };
  }
  if (!(await verifyEd25519(signingKey, spk, sigUrl))) {
    return { ok: false, reason: 'spk_signature does not verify under the bundle’s signing_key' };
  }
  if (!opts.deviceKeys) {
    return { ok: false, reason: `no device key reader to bind ${did}’s bundle` };
  }

  const kid = await deriveKid(signingKey);
  let found: FoundKey | null;
  try {
    found = await opts.deviceKeys.keyFor(did, kid);
  } catch (err) {
    return {
      ok: false,
      reason: `could not read ${did}’s device keys from its PDS: ${err instanceof Error ? err.message : String(err)}`,
      retry: true,
    };
  }
  if (found === null) {
    return {
      ok: false,
      reason: `bundle signing_key is not a device key published in ${did}’s PDS (not yet, or not theirs)`,
      retry: true,
    };
  }
  if (found.source !== 'IdentityRecord') {
    return {
      ok: false,
      reason: `bundle signing_key is vouched for by ${found.source}, not published in ${did}’s PDS`,
    };
  }
  if (!bytesEqual(found.publicKey, signingKey)) {
    return { ok: false, reason: 'bundle signing_key is not the device key its kid names' };
  }
  const nowSecs = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (found.retiredAt !== null) {
    return { ok: false, reason: `bundle signing_key is a device key ${did} has retired or let expire` };
  }
  if (found.expiresAt !== null && found.expiresAt <= nowSecs) {
    return { ok: false, reason: `bundle signing_key is a device key ${did} has retired or let expire` };
  }
  return { ok: true };
}

async function bindDidKey(did: string, bundle: BindableBundle, spk: Uint8Array): Promise<BindingResult> {
  let didPub: Uint8Array;
  try {
    didPub = decodeMultibaseEd25519(did.slice('did:key:'.length));
  } catch {
    return { ok: false, reason: 'did:key is not an ed25519 key' };
  }
  if (!bundle.signing_key) return { ok: false, reason: 'bundle has no signing_key; cannot bind it to the did:key' };
  let signingKey: Uint8Array;
  try {
    signingKey = decodeB64(bundle.signing_key);
  } catch {
    return { ok: false, reason: 'malformed signing_key' };
  }
  if (!bytesEqual(signingKey, didPub)) return { ok: false, reason: 'bundle signing_key is not the did:key\'s key' };
  let sigUrl: string;
  try {
    sigUrl = b64url(decodeB64(bundle.spk_signature));
  } catch {
    return { ok: false, reason: 'malformed spk_signature' };
  }
  if (!(await verifyEd25519(didPub, spk, sigUrl))) {
    return { ok: false, reason: 'spk_signature does not verify under the did:key' };
  }
  return { ok: true };
}

// ── Reading device keys from the PDS ──

/** How long a DID's device key listing answers before it is read again. */
export const DEVICE_KEYS_TTL_MS = 10 * 60 * 1000;
/** How soon a kid the held listing lacks lists the DID again. */
export const DEVICE_KEYS_RELIST_MS = 15 * 1000;

/**
 * A DID's device keys read straight from its PDS: `com.atproto.repo.listRecords`
 * at the PDS its DID document names, each record kept only if its repository
 * proof checks under the account's `#atproto` key. No freeq host is asked,
 * not for the listing and not for a key, so every answer is `IdentityRecord`.
 *
 * A DID's listing is kept for `ttlMs`, so retirements land within that time;
 * a kid the listing lacks lists the DID again once the listing is older than
 * `relistAfterMs`, so a device key published just after its owner joined is
 * found on a later pass. Failures are not kept.
 */
export class PdsDeviceKeys implements DeviceKeySource {
  private readonly listings = new Map<string, { records: unknown[]; at: number }>();
  private readonly inFlight = new Map<string, Promise<unknown[]>>();
  private readonly proven = new Set<string>();
  private readonly proving = new Map<string, Promise<boolean>>();
  private readonly ttlMs: number;
  private readonly relistAfterMs: number;
  private readonly now: () => number;

  constructor(
    private readonly reader: RecordReader,
    opts: { ttlMs?: number; relistAfterMs?: number; now?: () => number } = {},
  ) {
    this.ttlMs = opts.ttlMs ?? DEVICE_KEYS_TTL_MS;
    this.relistAfterMs = opts.relistAfterMs ?? DEVICE_KEYS_RELIST_MS;
    this.now = opts.now ?? (() => Date.now());
  }

  async keyFor(did: string, kid: string): Promise<FoundKey | null> {
    let held = this.listings.get(did);
    if (held === undefined || this.now() - held.at >= this.ttlMs) {
      await this.list(did);
      held = this.listings.get(did)!;
    }
    let found = await this.fromRecords(did, kid, held.records);
    if (found === null && this.now() - held.at >= this.relistAfterMs) {
      await this.list(did);
      found = await this.fromRecords(did, kid, this.listings.get(did)!.records);
    }
    return found;
  }

  /** Drop what is held for `did`, so the next ask lists it again. */
  forget(did: string): void {
    this.listings.delete(did);
  }

  private list(did: string): Promise<unknown[]> {
    let pending = this.inFlight.get(did);
    if (pending === undefined) {
      const started = (async () => {
        const { fetch, resolveDid } = this.reader;
        const entries = await listRecordEntries(fetch, resolveDid, did, DEVICE_KEY_TYPE);
        const records = await provenRecords(fetch, resolveDid, did, DEVICE_KEY_TYPE, entries, this.proven, this.proving);
        this.listings.set(did, { records, at: this.now() });
        return records;
      })().finally(() => {
        if (this.inFlight.get(did) === started) this.inFlight.delete(did);
      });
      this.inFlight.set(did, started);
      pending = started;
    }
    return pending;
  }

  private async fromRecords(did: string, kid: string, records: unknown[]): Promise<FoundKey | null> {
    const now = new Date(this.now());
    const match = (await deviceKeyHistory(did, records)).find((k) => k.kid === kid);
    if (match === undefined || match.createdAt.getTime() > now.getTime()) return null;
    let key: Uint8Array;
    try {
      key = decodeMultibaseEd25519(match.publicKeyMultibase);
    } catch {
      return null;
    }
    if ((await deriveKid(key)) !== kid) return null;
    const gone = retiredOrExpired(match, now);
    return {
      publicKey: key,
      source: 'IdentityRecord',
      retiredAt: gone ? Math.floor(match.retiredAt!.getTime() / 1000) : null,
      expiresAt: Math.floor(match.expiresAt.getTime() / 1000),
    };
  }
}

// ── Small helpers ──

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Standard or url-safe base64, padded or not. */
function decodeB64(s: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) throw new Error('not base64');
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
