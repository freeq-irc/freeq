/**
 * Instant rooms in the browser — see docs/INSTANT-ROOMS.md ("Web").
 *
 * A room is a `+i +E` channel whose traffic is EG1 group ciphertext. The
 * group secret for each epoch is sealed (EGK1) to every member's X25519
 * pre-key and parked server-blind at `/api/v1/channels/{ch}/groupkeys`.
 * This module is the web client's side of that:
 *
 *  - after we join a room, fetch the keys sealed to us, open them with the
 *    e2ee identity this browser already publishes, and hand the SDK a
 *    `ChannelCipher` so `say()` encrypts and inbound traffic decrypts;
 *  - when nothing is sealed to us yet, say so and poll until a member
 *    seals it (or we give up after a while);
 *  - steward duty: once we hold the latest epoch, seal it to roster members
 *    who lack it — on our own key load and whenever somebody joins. The
 *    founder also mints epoch 1 when the room has none yet.
 *
 * Opened secrets are persisted (keyed by DID + channel) so a reload reads
 * without waiting for a steward again: in IndexedDB, encrypted under a
 * non-extractable AES-GCM key, or in memory only when IndexedDB is not there
 * (lib/room-secret-store.ts). Loading them is async; anything that arrived as
 * ciphertext before they loaded is revealed once the cipher is installed.
 *
 * Nothing here logs a token or a secret.
 */

import {
  PdsDeviceKeys,
  createGroup,
  getIdentityX25519Secret,
  makeDidResolver,
  makeGroupCipher,
  openSealed,
  sealFor,
  sealedFromWire,
  sealedToWire,
  verifyBundleBinding as sdkVerifyBundleBinding,
  type BindingResult,
  type ChannelCipher,
  type DeviceKeySource,
  type GroupState,
} from '@freeq/sdk';
import { useStore, type RoomState } from '../store';
import { isRoomChannel, roomInviteUrl } from './room-link';
import { getRoomSecretStore, type RoomSecretStore } from './room-secret-store';

// ── Server shapes ──

export interface RoomMember {
  did: string;
  joined_at: number;
  online: boolean;
  /** Epochs this member already holds a sealed key for. */
  epochs: number[];
}

export interface RoomInfo {
  channel: string;
  topic: string | null;
  founder_did: string;
  created_at: number;
  last_activity: number;
  expires_at: number;
  latest_epoch: number | null;
  members: RoomMember[];
}

interface PreKeyBundle {
  did?: string;
  identity_key: string;
  signed_pre_key: string;
  spk_signature: string;
  spk_id?: number;
  signing_key?: string;
}

// ── Dependencies (injectable for tests) ──

/** The slice of `FreeqClient` this module touches. */
export interface RoomsClient {
  readonly apiBearer: string | null;
  readonly authDid: string | null;
  readonly nick: string;
  setChannelCipher(channel: string, cipher: ChannelCipher | null): void;
  getChannelCipher(channel: string): ChannelCipher | null;
}

export interface X25519Pair {
  secret: Uint8Array;
  publicKey: Uint8Array;
}

export interface RoomsDeps {
  getClient(): RoomsClient | null;
  fetch(input: string, init?: RequestInit): Promise<Response>;
  /** This browser's X25519 identity; null until e2ee has initialised. */
  identity(): X25519Pair | null;
  systemMessage(channel: string, text: string): void;
  /** A key was just adopted: decrypt whatever this channel already shows as
   *  ciphertext (history replayed before the key arrived). */
  revealCiphertext?(channel: string, cipher: ChannelCipher): void;
  setRoomState(channel: string, patch: Partial<RoomState>): void;
  clearRoomState(channel: string): void;
  /** Where opened secrets persist; null disables persistence. */
  secrets: RoomSecretStore | null;
  sleep(ms: number): Promise<void>;
  /** REST origin, '' for same-origin. */
  origin: string;
  /** Poll interval / budget while waiting for a key. */
  pollMs: number;
  pollMaxMs: number;
  /** How long to wait for the bearer and the e2ee identity to appear. */
  readyWaitMs: number;
  stewardDebounceMs: number;
  /**
   * Where a did:plc member's published device keys are read, to bind their
   * pre-key bundle to their DID. The app reads each member's own PDS
   * (`PdsDeviceKeys`); without one, did:plc members are never sealed to.
   */
  deviceKeys?: DeviceKeySource;
  /** Delays before each further steward pass while a member is refused for a
   *  reason that may pass (their device key record not published yet).
   *  Default 5 s, 15 s, 45 s, 2 min. */
  stewardRetryMs?: number[];
}

/** Steward retry delays when none are given. */
export const STEWARD_RETRY_MS = [5_000, 15_000, 45_000, 120_000];

export interface StewardResult {
  sealed: string[];
  /** `retry`: the refusal may pass later, and another pass is scheduled. */
  skipped: Array<{ did: string; reason: string; retry?: boolean }>;
}

export interface Rooms {
  onChannelJoined(channel: string, isEncrypted: boolean): void;
  onModeChanged(channel: string, mode: string): void;
  onMemberJoined(channel: string, nick: string): void;
  onChannelLeft(channel: string): void;
  loadRoomKeys(channel: string): Promise<boolean>;
  stewardPass(channel: string): Promise<StewardResult>;
  createInvite(channel: string, opts?: { inviteTtlSecs?: number; maxUses?: number }): Promise<{ invite: string; url: string; expiresAt: number | null }>;
  info(channel: string): Promise<RoomInfo | null>;
  /** True when we hold at least one epoch for this channel. */
  holdsKey(channel: string): boolean;
  /** The epochs we hold, as group states. */
  states(channel: string): GroupState[];
  /** Forget in-memory state (a new connection). Persisted secrets stay. */
  reset(): void;
}

// ── Per-channel bookkeeping ──

interface Tracked {
  channel: string;
  epochs: Map<number, Uint8Array>;
  loading: Promise<boolean> | null;
  polling: boolean;
  pollGen: number;
  stewardTimer: ReturnType<typeof setTimeout> | null;
  stewardRunning: boolean;
  stewardAgain: boolean;
  founderDid: string | null;
  latestEpoch: number | null;
  left: boolean;
  /** A steward pass scheduled because a member's refusal may pass. */
  retryTimer: ReturnType<typeof setTimeout> | null;
  /** Retries spent since the last pass with nothing to retry. */
  retries: number;
  /** `did reason` refusals already shown in the room. */
  refusalsShown: Set<string>;
}

export function createRooms(deps: RoomsDeps): Rooms {
  const tracked = new Map<string, Tracked>();

  const track = (channel: string): Tracked => {
    const ch = channel.toLowerCase();
    let t = tracked.get(ch);
    if (!t) {
      t = {
        channel: ch,
        epochs: new Map(),
        loading: null,
        polling: false,
        pollGen: 0,
        stewardTimer: null,
        stewardRunning: false,
        stewardAgain: false,
        founderDid: null,
        latestEpoch: null,
        left: false,
        retryTimer: null,
        retries: 0,
        refusalsShown: new Set(),
      };
      tracked.set(ch, t);
    }
    return t;
  };

  const states = (channel: string): GroupState[] => {
    const t = tracked.get(channel.toLowerCase());
    if (!t) return [];
    return [...t.epochs.entries()].map(([epoch, secret]) => ({ channel: t.channel, epoch, secret }));
  };

  const heldEpoch = (t: Tracked): number | null => {
    let best: number | null = null;
    for (const e of t.epochs.keys()) if (best === null || e > best) best = e;
    return best;
  };

  // ── Readiness ──

  async function waitFor<T>(probe: () => T | null): Promise<T | null> {
    const step = 200;
    for (let waited = 0; ; waited += step) {
      const v = probe();
      if (v !== null && v !== undefined) return v;
      if (waited >= deps.readyWaitMs) return null;
      await deps.sleep(step);
    }
  }

  /** The authenticated client, once its API bearer has landed. */
  const readyClient = (): Promise<RoomsClient | null> =>
    waitFor(() => {
      const c = deps.getClient();
      return c && c.apiBearer && c.authDid ? c : null;
    });

  const readyIdentity = (): Promise<X25519Pair | null> => waitFor(() => deps.identity());

  // ── REST ──

  async function api(client: RoomsClient, method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown): Promise<{ ok: boolean; status: number; data: unknown }> {
    const headers: Record<string, string> = { Authorization: `Bearer ${client.apiBearer}` };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const resp = await deps.fetch(`${deps.origin}${path}`, init);
    let data: unknown = null;
    try { data = await resp.json(); } catch { data = null; }
    return { ok: resp.ok, status: resp.status, data };
  }

  const groupkeysPath = (ch: string) => `/api/v1/channels/${encodeURIComponent(ch)}/groupkeys`;
  const roomPath = (ch: string) => `/api/v1/rooms/${encodeURIComponent(ch)}`;

  async function fetchInfo(client: RoomsClient, ch: string): Promise<RoomInfo | null> {
    const res = await api(client, 'GET', roomPath(ch));
    if (!res.ok || !res.data || typeof res.data !== 'object') return null;
    const raw = res.data as Partial<RoomInfo>;
    if (typeof raw.founder_did !== 'string') return null;
    return {
      channel: raw.channel ?? ch,
      topic: raw.topic ?? null,
      founder_did: raw.founder_did,
      created_at: raw.created_at ?? 0,
      last_activity: raw.last_activity ?? 0,
      expires_at: raw.expires_at ?? 0,
      latest_epoch: typeof raw.latest_epoch === 'number' ? raw.latest_epoch : null,
      members: (raw.members ?? []).map((m) => ({ ...m, epochs: Array.isArray(m.epochs) ? m.epochs : [] })),
    };
  }

  /** Fetch the keys sealed to us and open any we do not hold yet. */
  async function fetchAndOpen(client: RoomsClient, t: Tracked, me: X25519Pair): Promise<{ ok: boolean; status: number; opened: number }> {
    const res = await api(client, 'GET', groupkeysPath(t.channel));
    if (!res.ok) return { ok: false, status: res.status, opened: 0 };
    const keys = ((res.data as { keys?: Array<{ epoch: number; sealed: string }> })?.keys) ?? [];
    let opened = 0;
    for (const { epoch, sealed } of keys) {
      if (typeof epoch !== 'number' || typeof sealed !== 'string') continue;
      if (t.epochs.has(epoch)) continue;
      const parsed = sealedFromWire(sealed);
      if (!parsed) continue;
      const state = await openSealed(parsed, me);
      if (!state) continue;
      t.epochs.set(state.epoch, state.secret);
      opened++;
    }
    return { ok: true, status: res.status, opened };
  }

  // ── Cipher install / persistence / UI ──

  function installCipher(client: RoomsClient, t: Tracked): void {
    if (client.getChannelCipher(t.channel)) return; // the getter already sees new epochs
    client.setChannelCipher(t.channel, makeGroupCipher(() => states(t.channel)));
  }

  /** Write what we hold. Fire and forget: the store applies writes in order,
   *  and every write is the whole (only ever growing) set of epochs. */
  function persist(did: string, t: Tracked): void {
    if (!deps.secrets || t.epochs.size === 0) return;
    deps.secrets.save(did, t.channel, new Map(t.epochs)).catch(() => undefined);
  }

  async function restore(did: string, t: Tracked): Promise<void> {
    if (!deps.secrets) return;
    try {
      const saved = await deps.secrets.load(did, t.channel);
      for (const [epoch, secret] of saved) {
        if (!Number.isInteger(epoch) || epoch < 1 || t.epochs.has(epoch)) continue;
        if (secret.length === 32) t.epochs.set(epoch, secret);
      }
    } catch { /* unreadable: start over */ }
  }

  /** After epochs changed: install the cipher, persist, tell the UI. */
  function adopt(client: RoomsClient, t: Tracked, announce: boolean): void {
    installCipher(client, t);
    persist(client.authDid!, t);
    const cipher = client.getChannelCipher(t.channel);
    if (cipher) deps.revealCiphertext?.(t.channel, cipher);
    const held = heldEpoch(t);
    deps.setRoomState(t.channel, { isRoom: true, hasKey: held !== null, heldEpoch: held, waiting: false });
    if (announce && held !== null) deps.systemMessage(t.channel, `🔒 Room key loaded (epoch ${held})`);
  }

  function noteInfo(t: Tracked, info: RoomInfo): void {
    t.founderDid = info.founder_did;
    t.latestEpoch = info.latest_epoch;
    deps.setRoomState(t.channel, {
      isRoom: true,
      founderDid: info.founder_did,
      latestEpoch: info.latest_epoch,
      expiresAt: info.expires_at || null,
    });
  }

  const holdsLatest = (t: Tracked): boolean => t.latestEpoch !== null && t.epochs.has(t.latestEpoch);

  // ── Loading ──

  async function load(t: Tracked): Promise<boolean> {
    const client = await readyClient();
    if (!client || t.left) return false; // a guest: nothing can be sealed to us
    const me = await readyIdentity();
    if (!me || t.left) {
      if (isRoomChannel(t.channel)) deps.systemMessage(t.channel, 'Encryption identity is not ready, so the room key cannot be opened. Reload to try again.');
      return false;
    }
    const did = client.authDid!;
    await restore(did, t);
    if (t.left) return false;

    const got = await fetchAndOpen(client, t, me);
    const info = await fetchInfo(client, t.channel);
    if (t.left) return false;

    if (info) noteInfo(t, info);
    else if (isRoomChannel(t.channel)) deps.setRoomState(t.channel, { isRoom: true });
    else if (t.epochs.size === 0) {
      // A `+E` channel that is not a room and has nothing sealed to us: the
      // passphrase (ENC1) path owns it. Leave it alone.
      tracked.delete(t.channel);
      return false;
    }

    if (t.epochs.size > 0) adopt(client, t, got.opened > 0);

    // Steward duty on arrival: the founder mints epoch 1 if there is none;
    // anyone holding the latest epoch seals it to those who lack it.
    if (info && (holdsLatest(t) || (info.latest_epoch === null && info.founder_did === did))) {
      await runSteward(t);
    }

    if (t.epochs.size === 0) {
      deps.setRoomState(t.channel, { isRoom: true, hasKey: false, waiting: true });
      deps.systemMessage(t.channel, 'Waiting for a member to seal the room key to you…');
      startPolling(t);
      return false;
    }
    return true;
  }

  function startPolling(t: Tracked): void {
    if (t.polling) return;
    t.polling = true;
    const gen = ++t.pollGen;
    void (async () => {
      let waited = 0;
      try {
        while (!t.left && t.pollGen === gen && waited < deps.pollMaxMs) {
          await deps.sleep(deps.pollMs);
          waited += deps.pollMs;
          if (t.left || t.pollGen !== gen) return;
          const client = deps.getClient();
          const me = deps.identity();
          if (!client || !client.apiBearer || !client.authDid || !me) continue;
          const got = await fetchAndOpen(client, t, me);
          if (t.left || t.pollGen !== gen) return;
          if (got.opened > 0) {
            adopt(client, t, true);
            const info = await fetchInfo(client, t.channel);
            if (info) noteInfo(t, info);
            if (holdsLatest(t)) await runSteward(t);
            return;
          }
        }
        if (!t.left && t.pollGen === gen && t.epochs.size === 0) {
          deps.setRoomState(t.channel, { waiting: false });
          deps.systemMessage(t.channel, 'No room key arrived. Ask a member to reopen the room, or rejoin from the invite link.');
        }
      } finally {
        if (t.pollGen === gen) t.polling = false;
      }
    })();
  }

  // ── Steward ──

  async function runSteward(t: Tracked): Promise<void> {
    if (t.stewardRunning) { t.stewardAgain = true; return; }
    t.stewardRunning = true;
    try {
      await stewardPass(t.channel);
    } catch { /* transient; the next join or load tries again */ }
    finally { t.stewardRunning = false; }
    if (t.stewardAgain) {
      t.stewardAgain = false;
      scheduleSteward(t);
    }
  }

  function scheduleSteward(t: Tracked): void {
    if (t.stewardTimer) clearTimeout(t.stewardTimer);
    t.stewardTimer = setTimeout(() => {
      t.stewardTimer = null;
      void runSteward(t);
    }, deps.stewardDebounceMs);
  }

  async function postEpoch(client: RoomsClient, ch: string, state: GroupState, targets: Array<[string, Uint8Array]>): Promise<string[]> {
    const keys: Record<string, string> = {};
    for (const [did, pub] of targets) keys[did] = sealedToWire(await sealFor(state, pub));
    const res = await api(client, 'POST', groupkeysPath(ch), { epoch: state.epoch, keys });
    if (!res.ok) throw new Error(`POST groupkeys epoch ${state.epoch}: HTTP ${res.status}`);
    return serverSkipped((res.data as { skipped?: unknown })?.skipped);
  }

  async function stewardPass(channel: string): Promise<StewardResult> {
    const ch = channel.toLowerCase();
    const t = track(ch);
    const sealed: string[] = [];
    const skipped: StewardResult['skipped'] = [];
    const client = deps.getClient();
    const me = deps.identity();
    if (!client || !client.apiBearer || !client.authDid || !me) return { sealed, skipped };
    const did = client.authDid;

    const info = await fetchInfo(client, ch);
    if (!info || t.left) return { sealed, skipped };
    noteInfo(t, info);

    let latest = info.latest_epoch;
    if (latest === null) {
      if (info.founder_did !== did) return { sealed, skipped };
      const state = createGroup(ch);
      await postEpoch(client, ch, state, [[did, me.publicKey]]);
      t.epochs.set(state.epoch, state.secret);
      t.latestEpoch = state.epoch;
      latest = state.epoch;
      adopt(client, t, false);
      deps.setRoomState(ch, { latestEpoch: latest });
      deps.systemMessage(ch, '🔑 Created the room key (epoch 1)');
    }

    const held = states(ch);
    if (!held.some((s) => s.epoch === latest)) {
      // Not holding the current key: nothing we seal would let anyone read
      // current traffic, so hand out nothing rather than stale epochs.
      for (const m of info.members) {
        if (m.did !== did && !m.epochs.includes(latest)) skipped.push({ did: m.did, reason: `we do not hold epoch ${latest}` });
      }
      return { sealed, skipped };
    }

    // epoch → { did → EGK1 wire }
    const batches = new Map<number, Record<string, string>>();
    for (const member of info.members) {
      if (member.did === did) continue;
      if (member.epochs.includes(latest)) continue;
      const missing = held.filter((s) => !member.epochs.includes(s.epoch));
      if (missing.length === 0) continue;
      const pub = await memberIdentityKey(member.did);
      if (!pub.ok) {
        skipped.push({ did: member.did, reason: pub.reason, ...(pub.retry ? { retry: true } : {}) });
        // A bundle that does not bind to the DID is said once per reason:
        // the room should know why someone cannot read yet.
        const said = `${member.did} ${pub.reason}`;
        if (pub.binding && !t.refusalsShown.has(said)) {
          t.refusalsShown.add(said);
          deps.systemMessage(ch, `⚠️ Not sealing the room key to ${member.did}${pub.retry ? ' yet' : ''}: ${pub.reason}${pub.retry ? '. Will check again.' : ''}`);
        }
        continue;
      }
      for (const state of missing) {
        const wire = sealedToWire(await sealFor(state, pub.key));
        let batch = batches.get(state.epoch);
        if (!batch) { batch = {}; batches.set(state.epoch, batch); }
        batch[member.did] = wire;
      }
      sealed.push(member.did);
    }

    for (const [epoch, keys] of [...batches.entries()].sort((a, b) => a[0] - b[0])) {
      const res = await api(client, 'POST', groupkeysPath(ch), { epoch, keys });
      if (!res.ok) throw new Error(`POST groupkeys epoch ${epoch}: HTTP ${res.status}`);
      for (const skippedDid of serverSkipped((res.data as { skipped?: unknown })?.skipped)) {
        if (!skipped.some((s) => s.did === skippedDid)) skipped.push({ did: skippedDid, reason: 'not on the roster' });
      }
    }
    if (sealed.length > 0) {
      deps.systemMessage(ch, `🔑 Sealed the room key to ${sealed.length === 1 ? 'a new member' : `${sealed.length} new members`}`);
    }
    scheduleRetry(t, skipped.some((s) => s.retry));
    return { sealed, skipped };
  }

  /**
   * Another pass later when this one refused someone for a reason that may
   * pass (their device key record not in their PDS yet): at each of
   * `stewardRetryMs`, until a pass has nothing left to retry.
   */
  function scheduleRetry(t: Tracked, wanted: boolean): void {
    if (!wanted) { t.retries = 0; return; }
    const delays = deps.stewardRetryMs ?? STEWARD_RETRY_MS;
    if (t.retryTimer || t.left || t.retries >= delays.length) return;
    const delay = delays[t.retries++];
    t.retryTimer = setTimeout(() => {
      t.retryTimer = null;
      if (!t.left) void runSteward(t);
    }, delay);
  }

  /** A member's X25519 identity key, after checking the bundle belongs to them.
   *  `binding`: refused because the bundle does not bind to the DID. */
  async function memberIdentityKey(
    did: string,
  ): Promise<{ ok: true; key: Uint8Array } | { ok: false; reason: string; retry?: boolean; binding?: boolean }> {
    let bundle: PreKeyBundle | null;
    try {
      const resp = await deps.fetch(`${deps.origin}/api/v1/keys/${encodeURIComponent(did)}`);
      if (resp.status === 404) return { ok: false, reason: 'no pre-key bundle published' };
      if (!resp.ok) return { ok: false, reason: `pre-key bundle fetch failed: HTTP ${resp.status}` };
      const data = (await resp.json()) as { bundle?: PreKeyBundle } & Partial<PreKeyBundle>;
      bundle = data.bundle ?? (typeof data.identity_key === 'string' ? (data as PreKeyBundle) : null);
    } catch (err) {
      return { ok: false, reason: `pre-key bundle fetch failed: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (!bundle) return { ok: false, reason: 'no pre-key bundle published' };
    let identityKey: Uint8Array;
    let spk: Uint8Array;
    try {
      identityKey = unb64(bundle.identity_key);
      spk = unb64(bundle.signed_pre_key);
    } catch {
      return { ok: false, reason: 'malformed pre-key bundle' };
    }
    if (identityKey.length !== 32 || spk.length !== 32) return { ok: false, reason: 'malformed pre-key bundle' };
    const check = await verifyBundleBinding(did, bundle, spk, deps.deviceKeys);
    if (!check.ok) return { ...check, binding: true };
    return { ok: true, key: identityKey };
  }

  // ── Public surface ──

  const rooms: Rooms = {
    onChannelJoined(channel, isEncrypted) {
      const ch = channel.toLowerCase();
      if (!isRoomChannel(ch) && !isEncrypted) return;
      const t = track(ch);
      t.left = false;
      void rooms.loadRoomKeys(ch);
    },
    onModeChanged(channel, mode) {
      if (mode !== '+E') return;
      const ch = channel.toLowerCase();
      if (tracked.has(ch)) return;
      void rooms.loadRoomKeys(ch);
    },
    onMemberJoined(channel, nick) {
      const t = tracked.get(channel.toLowerCase());
      if (!t || t.left) return;
      const client = deps.getClient();
      if (client?.nick && nick.toLowerCase() === client.nick.toLowerCase()) return;
      // Only a holder of the current key (or the founder of a room that has
      // none yet) has anything to give a newcomer.
      const founderOfKeyless = t.latestEpoch === null && !!t.founderDid && t.founderDid === client?.authDid;
      if (!holdsLatest(t) && !founderOfKeyless) return;
      scheduleSteward(t);
    },
    onChannelLeft(channel) {
      const ch = channel.toLowerCase();
      const t = tracked.get(ch);
      if (!t) return;
      t.left = true;
      t.pollGen++;
      t.polling = false;
      if (t.stewardTimer) { clearTimeout(t.stewardTimer); t.stewardTimer = null; }
      if (t.retryTimer) { clearTimeout(t.retryTimer); t.retryTimer = null; }
      tracked.delete(ch);
      deps.getClient()?.setChannelCipher(ch, null);
      deps.clearRoomState(ch);
    },
    loadRoomKeys(channel) {
      const t = track(channel);
      if (t.loading) return t.loading;
      t.loading = load(t).finally(() => { t.loading = null; });
      return t.loading;
    },
    stewardPass,
    async createInvite(channel, opts = {}) {
      const ch = channel.toLowerCase();
      const client = deps.getClient();
      if (!client || !client.apiBearer) throw new Error('not signed in');
      const body: Record<string, unknown> = {};
      if (opts.inviteTtlSecs !== undefined) body.invite_ttl_secs = opts.inviteTtlSecs;
      if (opts.maxUses !== undefined) body.max_uses = opts.maxUses;
      const res = await api(client, 'POST', `${roomPath(ch)}/invites`, body);
      const data = (res.data ?? {}) as { invite?: string; url?: string; invite_expires_at?: number; error?: string };
      if (!res.ok || typeof data.invite !== 'string') {
        throw new Error(typeof data.error === 'string' ? data.error : `HTTP ${res.status}`);
      }
      deps.setRoomState(ch, { isRoom: true, inviteToken: data.invite });
      const origin = deps.origin || (typeof location !== 'undefined' ? location.origin : '');
      return { invite: data.invite, url: data.url ?? roomInviteUrl(origin, ch, data.invite), expiresAt: data.invite_expires_at ?? null };
    },
    async info(channel) {
      const client = deps.getClient();
      if (!client || !client.apiBearer) return null;
      return fetchInfo(client, channel.toLowerCase());
    },
    holdsKey(channel) {
      return (tracked.get(channel.toLowerCase())?.epochs.size ?? 0) > 0;
    },
    states,
    reset() {
      for (const t of tracked.values()) {
        t.left = true;
        t.pollGen++;
        if (t.stewardTimer) clearTimeout(t.stewardTimer);
        if (t.retryTimer) clearTimeout(t.retryTimer);
      }
      tracked.clear();
    },
  };
  return rooms;
}

// ── Bundle ↔ DID binding ──

/**
 * Does this pre-key bundle belong to `did`? The SDK's rule
 * (`@freeq/sdk` `verifyBundleBinding`): a `did:key` bundle must be signed by
 * the DID's own Ed25519 key; any other DID's (`did:plc`) must be signed by a
 * live device key the account published as an `at.freeq.deviceKey` record in
 * its own PDS, read through `deviceKeys` — never on the freeq host's word —
 * and `spk_signature` must verify under it. Without `deviceKeys` a did:plc
 * bundle is refused. A refusal that may pass later carries `retry: true`.
 */
export async function verifyBundleBinding(
  did: string,
  bundle: { signing_key?: string; spk_signature: string; signed_pre_key: string },
  spkBytes?: Uint8Array,
  deviceKeys?: DeviceKeySource,
): Promise<BindingResult> {
  return sdkVerifyBundleBinding(did, bundle, { spk: spkBytes, deviceKeys });
}

// ── Small helpers ──

function serverSkipped(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .map((x) => (typeof x === 'string' ? x : x && typeof x === 'object' ? (x as { did?: unknown }).did : null))
    .filter((x): x is string => typeof x === 'string');
}

function unb64(s: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) throw new Error('not base64');
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── The app's singleton ──

let singleton: Rooms | null = null;
let clientProvider: (() => RoomsClient | null) | null = null;
let deviceKeyReader: PdsDeviceKeys | null = null;

/** The one reader of members' device keys, made on first use. */
function memberDeviceKeys(): PdsDeviceKeys {
  deviceKeyReader ??= new PdsDeviceKeys({ fetch: (target, init) => fetch(target, init), resolveDid: makeDidResolver() });
  return deviceKeyReader;
}

/**
 * `irc/client.ts` owns the SDK client and registers how to reach it here,
 * which keeps this module free of an import back into the bridge.
 */
export function setRoomsClientProvider(fn: () => RoomsClient | null): void {
  clientProvider = fn;
}

/** The rooms controller wired to the store, the SDK identity and `fetch`. */
export function getRooms(): Rooms {
  if (!singleton) {
    singleton = createRooms({
      getClient: () => clientProvider?.() ?? null,
      fetch: (input, init) => fetch(input, init),
      // Members' device keys come from their own PDS (resolved through the
      // PLC directory), never from this freeq host: that is what binds a
      // did:plc bundle to the DID.
      deviceKeys: { keyFor: (did, kid) => memberDeviceKeys().keyFor(did, kid) },
      identity: () => {
        const s = getIdentityX25519Secret();
        return s && 'secret' in s ? { secret: s.secret, publicKey: s.publicKey } : null;
      },
      systemMessage: (channel, text) => useStore.getState().addSystemMessage(channel, text),
      revealCiphertext: (channel, cipher) => {
        const ch = useStore.getState().channels.get(channel.toLowerCase());
        for (const m of ch?.messages ?? []) {
          if (!m.text || !cipher.isCiphertext(m.text)) continue;
          cipher.decrypt(m.text).then((plain) => {
            if (plain !== null) useStore.getState().revealMessage(channel, m.id, plain);
          }).catch(() => undefined);
        }
      },
      setRoomState: (channel, patch) => useStore.getState().setRoomState(channel, patch),
      clearRoomState: (channel) => useStore.getState().clearRoomState(channel),
      secrets: getRoomSecretStore(),
      sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
      origin: '',
      pollMs: 5_000,
      pollMaxMs: 5 * 60_000,
      readyWaitMs: 20_000,
      stewardDebounceMs: 500,
    });
  }
  return singleton;
}
