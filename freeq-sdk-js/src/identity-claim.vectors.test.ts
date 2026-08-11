/**
 * Replays every vector in the canonical `spec/identity-claims.json` against
 * this implementation — the same file the Rust SDK replays — so the two
 * implementations cannot drift apart silently. Also pins the imported copy in
 * `src/` byte-identical to the canonical file: the copy exists only because
 * this package's build root cannot reach outside `src/`.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  claimForMessage,
  claimForPerson,
  claimForSender,
  stampingEpochUnix,
  type PersonLookup,
} from './identity-claim';

const canonicalPath = join(__dirname, '../../spec/identity-claims.json');
const canonical = JSON.parse(readFileSync(canonicalPath, 'utf8'));

describe('identity-claim spec parity', () => {
  it('the copy this package imports is byte-identical to the canonical spec file', () => {
    const copy = readFileSync(join(__dirname, 'identity-claims.json'), 'utf8');
    const original = readFileSync(canonicalPath, 'utf8');
    expect(copy, 'refresh with: cp spec/identity-claims.json freeq-sdk-js/src/identity-claims.json').toBe(original);
  });

  it('the epoch is the documented constant', () => {
    expect(stampingEpochUnix()).toBe(1_785_542_400);
  });

  describe('message vectors', () => {
    for (const v of canonical.message_vectors) {
      it(v.name, () => {
        const i = v.input;
        const claim = claimForMessage({
          account: i.account,
          origin: i.origin,
          senderPresent: i.sender_present,
          senderLiveDid: i.sender_live_did,
          rowTimeUnix: i.row_time_unix,
        });
        expect(claim.state).toBe(v.expect.state);
        expect(claim.did).toBe(v.expect.did);
        expect(claim.line).toBe(v.expect.line);
      });
    }
  });

  describe('sender vectors', () => {
    for (const v of canonical.sender_vectors) {
      it(v.name, () => {
        const i = v.input;
        const claim = claimForSender(
          {
            account: i.account,
            origin: i.origin,
            senderPresent: i.sender_present,
            senderLiveDid: i.sender_live_did,
            rowTimeUnix: i.row_time_unix,
          },
          i.lookup as PersonLookup,
        );
        expect(claim.state).toBe(v.expect.state);
        expect(claim.did).toBe(v.expect.did);
        expect(claim.line).toBe(v.expect.line);
      });
    }
  });

  describe('person vectors', () => {
    for (const v of canonical.person_vectors) {
      it(v.name, () => {
        const i = v.input;
        const claim = claimForPerson({
          binding: i.binding,
          seenOnlyViaPeer: i.seen_only_via_peer,
          viaPeerOrigin: i.via_peer_origin,
          viaPeerHadAccount: i.via_peer_had_account,
          lookup: i.lookup as PersonLookup,
        });
        expect(claim.state).toBe(v.expect.state);
        expect(claim.did).toBe(v.expect.did);
        expect(claim.line).toBe(v.expect.line);
      });
    }
  });

  it('labels and flags come from the spec', () => {
    const c = claimForMessage({ account: 'did:plc:abc' });
    expect(c.label).toBe('AT Protocol identity');
    expect(c.showsMark).toBe(true);
    expect(c.needsKeyCard).toBe(true);
    expect(c.isPending).toBe(false);

    const pending = claimForPerson({ lookup: 'inFlight' });
    expect(pending.label).toBeNull();
    expect(pending.line).toBeNull();
    expect(pending.isPending).toBe(true);
    expect(pending.showsMark).toBe(false);
  });
});
