import { describe, expect, it } from 'vitest';

import { KeyLookup } from './key-lookup.js';
import { verifyLine } from './verdict.js';

const noNetwork = new KeyLookup(
  {
    fetch: async () => new Response('', { status: 404 }),
    resolveDid: async () => null,
  } as never,
  null,
  60_000,
);

describe('verifyLine', () => {
  it('calls a line with no signature unsigned', async () => {
    expect(await verifyLine({ tags: { account: 'did:plc:owner' }, target: 'me', body: 'yes abcde' }, noNetwork)).toEqual({
      state: 'unsigned',
    });
  });

  it('calls a malformed signature unverifiable, never valid', async () => {
    const v = await verifyLine(
      { tags: { account: 'did:plc:owner', '+freeq.at/sig': 'ed25519:kid:nope', msgid: '01J0000000000000000000000' }, target: 'me', body: 'yes abcde' },
      noNetwork,
    );
    expect(v.state).toBe('unverifiable');
  });

  it('does not call a well-formed signature it cannot check a device signature', async () => {
    const sig = `ed25519:abcdefgh:${'A'.repeat(86)}`;
    const v = await verifyLine(
      { tags: { account: 'did:plc:owner', '+freeq.at/sig': sig, msgid: '01J0000000000000000000000' }, target: 'me', body: 'yes abcde', ownDid: 'did:key:zSelf' },
      noNetwork,
    );
    expect(v.state).not.toBe('device');
  });
});
