// @vitest-environment jsdom
/**
 * The Devices list: every signing key the account has published, what state
 * it is in, and the one action each row offers.
 *
 * The records are built here with the SDK's own builders and folded by the
 * SDK's own rule, so the rows are read off real signed records rather than a
 * hand-written shape the component happens to accept.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, cleanup, screen, fireEvent, waitFor, within } from '@testing-library/react';

const DID = 'did:plc:devicelist';
const BROKER = 'https://broker.test.example';

// Two seams, both at a module boundary: what the list reads, and the key this
// browser holds. Hoisted so the mock factories can reach them.
const seam = vi.hoisted(() => ({
  rows: null as unknown,
  pair: null as CryptoKeyPair | null,
  published: true,
}));

vi.mock('../irc/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../irc/client')>();
  return { ...actual, listDeviceRows: async () => seam.rows };
});

// The panel reads notification preferences from IndexedDB on mount, which
// jsdom has none of.
vi.mock('../lib/db', () => ({
  getPreferences: async () => ({ notificationsEnabled: true, soundsEnabled: true }),
  setPreferences: async () => {},
}));

vi.mock('@freeq/sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@freeq/sdk')>();
  return {
    ...actual,
    // This browser's key store, without IndexedDB (jsdom has none).
    IndexedDbDeviceKeyStore: class {
      constructor(_did: string) {}
      async load() {
        return seam.pair
          ? {
              keyPair: seam.pair,
              createdAt: THIS_CREATED,
              ...(seam.published ? { recordUri: 'at://this' } : {}),
            }
          : null;
      }
      async save() {}
    },
  };
});

import {
  buildDeviceRecord,
  buildDeviceRetirement,
  recordKeyOf,
  type DeviceKeyRecord,
} from '@freeq/sdk';
import { SettingsPanel } from './SettingsPanel';
import * as client from '../irc/client';
import { useStore } from '../store';

const THIS_CREATED = '2026-01-02T00:00:00.000Z';
const OTHER_CREATED = '2026-02-03T00:00:00.000Z';
const GONE_CREATED = '2026-01-05T00:00:00.000Z';
// Recent, since a signed-out row is listed for 24 hours after its retirement.
const HOUR_MS = 60 * 60 * 1000;
const GONE_RETIRED = new Date(Date.now() - HOUR_MS).toISOString();

/** A signing key and the record announcing it, as the account would hold them. */
async function aDevice(label: string, createdAt: string) {
  const pair = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const key = await recordKeyOf(pair);
  const record = await buildDeviceRecord(key, DID, createdAt, label);
  return { pair, key, record, kid: record.kid };
}

let thisDevice: Awaited<ReturnType<typeof aDevice>>;
let otherDevice: Awaited<ReturnType<typeof aDevice>>;
let goneDevice: Awaited<ReturnType<typeof aDevice>>;
let records: DeviceKeyRecord[];

beforeEach(async () => {
  thisDevice = await aDevice('This browser', THIS_CREATED);
  otherDevice = await aDevice('Work laptop', OTHER_CREATED);
  goneDevice = await aDevice('Old phone', GONE_CREATED);
  const retirement = await buildDeviceRetirement(goneDevice.key, DID, goneDevice.kid, GONE_RETIRED);
  records = [thisDevice.record, otherDevice.record, goneDevice.record, retirement];
  seam.pair = thisDevice.pair;
  seam.published = true;
  localStorage.setItem('freeq-broker-base', BROKER);
  localStorage.setItem('freeq-broker-token', 'BT-TEST');

  useStore.getState().reset();
  useStore.setState({ authDid: DID });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** How the panel writes a date, so the expectations read the same recipe. */
const day = (iso: string) => new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' });

function panel() {
  return render(<SettingsPanel open onClose={() => {}} />);
}

/** The meta line of the row named `name`. */
function rowMeta(name: string): string {
  const row = screen.getByText(name).closest('[data-device-row]');
  if (!row) throw new Error(`no row for ${name}`);
  return row.querySelector('[data-device-meta]')!.textContent ?? '';
}

describe('the Devices list', () => {
  it('shows one row per key, with its state and its one action', async () => {
    seam.rows = await client.deviceRowsFrom(DID, records, {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });
    panel();
    await waitFor(() => screen.getByText('Work laptop'));

    // Newest key first.
    expect(screen.getAllByTestId('device-name').map((el) => el.textContent)).toEqual([
      'Work laptop',
      'Old phone',
      'This browser',
    ]);

    expect(rowMeta('Work laptop')).toBe(`Active · since ${day(OTHER_CREATED)}`);
    expect(rowMeta('Old phone')).toBe(`Signed out · ${day(GONE_RETIRED)}`);
    expect(rowMeta('This browser')).toBe(`Active · since ${day(THIS_CREATED)}`);

    // One action each: another live device can be signed out, a signed-out
    // one offers nothing, and this device is named rather than actionable.
    expect(screen.getAllByRole('button', { name: 'Sign out' })).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'This device' })).toBeNull();
    expect(screen.getByText('This device')).toBeTruthy();

    expect(
      screen.getByText(
        'A signed-out device has to sign in again before it can post as you. Messages it already sent stay signed.',
      ),
    ).toBeTruthy();
  });

  it('offers Publish key on this device until its key is in the account', async () => {
    seam.rows = await client.deviceRowsFrom(DID, [otherDevice.record], {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: false,
    });
    panel();
    await waitFor(() => screen.getByText('Work laptop'));

    expect(rowMeta(`${thisDevice.kid.slice(0, 8)}…`)).toBe('Key not published · this device');
    expect(screen.getByRole('button', { name: 'Publish key' })).toBeTruthy();
  });

  it('lists a signed-out device for 24 hours after its retirement, and not after', async () => {
    const recent = await aDevice('Recent phone', GONE_CREATED);
    const old = await aDevice('Old tablet', GONE_CREATED);
    const anHourAgo = new Date(Date.now() - HOUR_MS).toISOString();
    const twentyFiveHoursAgo = new Date(Date.now() - 25 * HOUR_MS).toISOString();
    seam.rows = await client.deviceRowsFrom(
      DID,
      [
        thisDevice.record,
        recent.record,
        await buildDeviceRetirement(recent.key, DID, recent.kid, anHourAgo),
        old.record,
        await buildDeviceRetirement(old.key, DID, old.kid, twentyFiveHoursAgo),
      ],
      { kid: thisDevice.kid, createdAt: THIS_CREATED, published: true },
    );
    panel();
    await waitFor(() => screen.getByText('Recent phone'));

    expect(rowMeta('Recent phone')).toBe(`Signed out · ${day(anHourAgo)}`);
    expect(screen.queryByText('Old tablet')).toBeNull();
  });

  it('writes a date as a short month and day', async () => {
    seam.rows = await client.deviceRowsFrom(DID, records, {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });
    panel();
    await waitFor(() => screen.getByText('Work laptop'));

    const short = new Date(OTHER_CREATED).toLocaleDateString([], { month: 'short', day: 'numeric' });
    expect(rowMeta('Work laptop')).toBe(`Active · since ${short}`);
    expect(rowMeta('Work laptop')).not.toContain(new Date(OTHER_CREATED).toLocaleDateString());
  });

  it('dates a signed-out device by the retirement that counts, not an ignored earlier one', async () => {
    // Signed by a key the account never published, so every client ignores it.
    const stranger = await aDevice('Stranger', '2026-01-01T00:00:00.000Z');
    const ignored = await buildDeviceRetirement(
      stranger.key,
      DID,
      goneDevice.kid,
      '2026-02-01T00:00:00.000Z',
    );
    const rows = await client.deviceRowsFrom(DID, [...records, ignored], {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });
    expect(rows.find((r) => r.kid === goneDevice.kid)?.date).toBe(GONE_RETIRED);
  });

  it('writes the retirement and tells the server when a device is signed out', async () => {
    client.setSaslCredentials('', DID, '', '');
    seam.rows = await client.deviceRowsFrom(DID, records, {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });

    const calls: { url: string; body: unknown }[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url, body: JSON.parse(String(init?.body ?? '{}')) });
        return new Response(JSON.stringify({ uri: 'at://x', ok: true }), { status: 200 });
      }),
    );

    panel();
    await waitFor(() => screen.getByText('Work laptop'));

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    const ask = screen.getByRole('dialog');
    expect(within(ask).getByText('Sign out Work laptop?')).toBeTruthy();
    expect(
      within(ask).getByText(
        'It will be signed out and will need to sign in again. Messages it already sent stay signed.',
      ),
    ).toBeTruthy();

    fireEvent.click(within(ask).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Sign out' }));

    await waitFor(() => expect(calls).toHaveLength(2));

    // The record names the key it retires and the key that signed it.
    expect(calls[0].url).toBe(`${BROKER}/enroll`);
    const posted = calls[0].body as { record: DeviceKeyRecord };
    expect(posted.record.revokes).toBe(otherDevice.kid);
    expect(posted.record.kid).toBe(thisDevice.kid);
    expect(posted.record.publicKeyMultibase).toBeUndefined();

    // Then the server, so the device's sessions and login token end.
    expect(calls[1].url).toBe('/api/v1/devices/sign-out');
    expect(calls[1].body).toEqual({ kid: otherDevice.kid });
  });

  it('opens the sign-out confirmation outside the Settings panel', async () => {
    seam.rows = await client.deviceRowsFrom(DID, records, {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });
    panel();
    await waitFor(() => screen.getByText('Work laptop'));
    const settings = screen.getByText('Work laptop').closest('.animate-slideIn');
    expect(settings).not.toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    const ask = screen.getByRole('dialog');
    expect(settings!.contains(ask)).toBe(false);
    expect(document.body.contains(ask)).toBe(true);
  });
});

describe('what signing a device out says', () => {
  const NOT_READY = "To sign out other devices, sign in and publish this device's key first.";
  const NO_STORAGE =
    "This browser won't let freeq store its key. Change your browser settings to allow this site to store data, or try another browser.";
  const NO_ANSWER =
    "Couldn't sign out Work laptop because your account provider didn't respond. Try again in a moment.";
  const NOT_CONNECTED =
    "Work laptop's key has been retired, so anything it sends now is flagged. It isn't connected to this server, so it may still be signed in somewhere else. To sign it out there too, open freeq on that server and sign it out from Devices.";
  const UNKNOWN_HERE =
    "Work laptop's key has been retired, so anything it sends now is flagged. It may still be signed in, here or somewhere else. To sign it out there too, open freeq on that server and sign it out from Devices.";
  const OTHER_FAILURE = "Couldn't sign out Work laptop. Try again.";
  const EVERY_MESSAGE = [NOT_READY, NO_STORAGE, NO_ANSWER, NOT_CONNECTED, UNKNOWN_HERE, OTHER_FAILURE];

  let calls: string[];

  /** The account provider and this server, answering by URL. */
  function answering(enroll: () => Response, server: () => Response) {
    calls = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        calls.push(url);
        return url === `${BROKER}/enroll` ? enroll() : server();
      }),
    );
  }

  const json = (status: number, body: unknown) => () =>
    new Response(JSON.stringify(body), { status });

  /** Open the panel and confirm signing Work laptop out. */
  async function signOutWorkLaptop() {
    seam.rows = await client.deviceRowsFrom(DID, records, {
      kid: thisDevice.kid,
      createdAt: THIS_CREATED,
      published: true,
    });
    panel();
    await waitFor(() => screen.getByText('Work laptop'));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  }

  /** The one message shown, and whether it is in the failure colour. */
  async function shown(text: string) {
    const line = await waitFor(() => screen.getByText(text));
    for (const other of EVERY_MESSAGE.filter((m) => m !== text)) {
      expect(screen.queryByText(other)).toBeNull();
    }
    return line.className.includes('text-red-400');
  }

  beforeEach(() => {
    client.setSaslCredentials('', DID, '', '');
  });

  it('asks for a sign-in and a published key when this device has no published key', async () => {
    seam.published = false;
    answering(json(200, { uri: 'at://x' }), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    expect(await shown(NOT_READY)).toBe(true);
    expect(calls, 'nothing is written').toEqual([]);
  });

  it('asks for a sign-in and a published key when nobody is signed in', async () => {
    client.setSaslCredentials('', '', '', '');
    answering(json(200, { uri: 'at://x' }), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    expect(await shown(NOT_READY)).toBe(true);
    expect(calls, 'nothing is written').toEqual([]);
  });

  it('says the browser will not keep a key when the store has none', async () => {
    seam.pair = null;
    answering(json(200, { uri: 'at://x' }), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    expect(await shown(NO_STORAGE)).toBe(true);
    expect(calls, 'nothing is written').toEqual([]);
  });

  it('says the account provider did not respond when it does not save the retirement', async () => {
    answering(json(502, 'PDS rejected record'), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    expect(await shown(NO_ANSWER)).toBe(true);
    expect(calls).toEqual([`${BROKER}/enroll`]);
  });

  it('still asks for a sign-in when the account provider refuses permission', async () => {
    answering(json(403, { error: 'insufficient_scope' }), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    await waitFor(() => screen.getByText('Sign in to continue'));
    for (const message of EVERY_MESSAGE) expect(screen.queryByText(message)).toBeNull();
  });

  it('leaves the upgrade bar down when a refused sign-out comes from a published key', async () => {
    expect(client.getDeviceKeyState().needsSignIn, 'the bar starts down').toBe(false);
    answering(json(403, { error: 'insufficient_scope' }), json(200, { ok: true, sessions_closed: 1 }));
    await signOutWorkLaptop();
    await waitFor(() => screen.getByText('Sign in to continue'));
    expect(client.getDeviceKeyState().needsSignIn).toBe(false);
  });

  it('marks the key unpublished when sign-out loads a key that is not published', async () => {
    // Loading an unpublished key is what marks this device's key unpublished;
    // sign-out then stops before writing anything.
    seam.published = false;
    answering(json(403, { error: 'insufficient_scope' }), json(200, { ok: true, sessions_closed: 1 }));
    await client.signOutDevice(otherDevice.kid);
    expect(client.getDeviceKeyState().published).toBe(false);

    // Back to a published browser key for the tests after this one.
    seam.published = true;
    await client.signOutDevice(otherDevice.kid);
  });

  it('notes the device is not connected here when the server closed no session', async () => {
    answering(
      json(200, { uri: 'at://x' }),
      json(200, { ok: true, sessions_closed: 0, tokens_revoked: 0 }),
    );
    await signOutWorkLaptop();
    expect(await shown(NOT_CONNECTED)).toBe(false);
  });

  it('notes the device may still be signed in when the server did not answer OK', async () => {
    answering(json(200, { uri: 'at://x' }), json(500, 'down'));
    await signOutWorkLaptop();
    expect(await shown(UNKNOWN_HERE)).toBe(false);
  });

  it('says to try again on any other failure', async () => {
    calls = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    await signOutWorkLaptop();
    expect(await shown(OTHER_FAILURE)).toBe(true);
  });

  it('says nothing when the retirement saved and the server closed its session', async () => {
    answering(json(200, { uri: 'at://x' }), json(200, { ok: true, sessions_closed: 1, tokens_revoked: 1 }));
    await signOutWorkLaptop();
    await waitFor(() => expect(calls).toHaveLength(2));
    await new Promise((r) => setTimeout(r, 20));
    for (const message of EVERY_MESSAGE) expect(screen.queryByText(message)).toBeNull();
  });
});
