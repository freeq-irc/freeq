import { describe, it, expect } from 'vitest';
import { generateDidKey } from '@freeq/sdk';
import {
  carryRoomKeys,
  clearRoomUpgrade,
  formatLinkMessage,
  loadRoomUpgrade,
  parseLinkMessage,
  saveRoomUpgrade,
  signRoomLink,
  verifyRoomLink,
  ROOM_UPGRADE_TTL_MS,
} from './room-upgrade';

function memStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    keys: () => [...m.keys()],
  };
}

const ROOM = '#r-quiet-copper-fox';
const ACCOUNT = 'did:plc:upgradeduser0000000000';

describe('the guest → identity link', () => {
  it('round-trips: the guest key vouches for the account it became', async () => {
    const guest = await generateDidKey();
    const sig = await signRoomLink(guest.signer, guest.did, ACCOUNT, ROOM);
    const text = formatLinkMessage('quiet-guest', guest.did, sig);
    expect(parseLinkMessage(text)).toEqual({ guestDid: guest.did, sig });
    expect(await verifyRoomLink(text, ACCOUNT, ROOM)).toEqual({ guestDid: guest.did });
  });

  it('is refused when someone else posts it', async () => {
    // Copying a link message into the room as a different account must not
    // claim the guest's history for that account.
    const guest = await generateDidKey();
    const sig = await signRoomLink(guest.signer, guest.did, ACCOUNT, ROOM);
    const text = formatLinkMessage('quiet-guest', guest.did, sig);
    expect(await verifyRoomLink(text, 'did:plc:someoneelse00000000000', ROOM)).toBeNull();
  });

  it('is refused in another room', async () => {
    const guest = await generateDidKey();
    const sig = await signRoomLink(guest.signer, guest.did, ACCOUNT, ROOM);
    const text = formatLinkMessage('quiet-guest', guest.did, sig);
    expect(await verifyRoomLink(text, ACCOUNT, '#r-other-room-here')).toBeNull();
  });

  it('is refused when the signature is not the guest key\'s', async () => {
    const guest = await generateDidKey();
    const impostor = await generateDidKey();
    const sig = await signRoomLink(impostor.signer, guest.did, ACCOUNT, ROOM);
    const text = formatLinkMessage('quiet-guest', guest.did, sig);
    expect(await verifyRoomLink(text, ACCOUNT, ROOM)).toBeNull();
  });

  it('ignores ordinary messages and malformed markers', () => {
    expect(parseLinkMessage('hello there')).toBeNull();
    expect(parseLinkMessage('[freeq-link:v1 did:plc:x abc]')).toBeNull();
    expect(parseLinkMessage('[freeq-link:v1 did:key:z6Mk!! abc]')).toBeNull();
  });
});

describe('the upgrade record', () => {
  it('survives the sign-in redirect and expires', () => {
    const storage = memStorage();
    const up = { guestDid: 'did:key:z6Mkguest', guestNick: 'quiet-guest', channel: ROOM, token: 'tok' };
    saveRoomUpgrade(up, storage, 1_000);
    expect(loadRoomUpgrade(storage, 1_000 + 60_000)).toMatchObject(up);
    expect(loadRoomUpgrade(storage, 1_000 + ROOM_UPGRADE_TTL_MS + 1)).toBeNull();
    saveRoomUpgrade(up, storage, 1_000);
    clearRoomUpgrade(storage);
    expect(loadRoomUpgrade(storage, 2_000)).toBeNull();
  });

  it('carries the room keys the guest held over to the new identity', () => {
    const storage = memStorage();
    storage.setItem(`freeq-room-keys:did:key:z6Mkguest:${ROOM}`, '{"1":"c2VjcmV0"}');
    const carried = carryRoomKeys('did:key:z6Mkguest', ACCOUNT, ROOM, storage);
    expect(carried).toBe(true);
    expect(storage.getItem(`freeq-room-keys:${ACCOUNT}:${ROOM}`)).toBe('{"1":"c2VjcmV0"}');
  });

  it('never overwrites keys the new identity already holds', () => {
    const storage = memStorage();
    storage.setItem(`freeq-room-keys:did:key:z6Mkguest:${ROOM}`, '{"1":"b2xk"}');
    storage.setItem(`freeq-room-keys:${ACCOUNT}:${ROOM}`, '{"1":"b2xk","2":"bmV3"}');
    expect(carryRoomKeys('did:key:z6Mkguest', ACCOUNT, ROOM, storage)).toBe(false);
    expect(storage.getItem(`freeq-room-keys:${ACCOUNT}:${ROOM}`)).toBe('{"1":"b2xk","2":"bmV3"}');
  });
});
