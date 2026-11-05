# Instant rooms: closing the known gaps (PR #118)

Started 2026-11-05. Branch: `instant-rooms`. Updated as work lands.

The gaps come from the PR's "Known limitations" and `docs/INSTANT-ROOMS.md`.

## 1. `did:plc` pre-key bundles are not bound to the DID — DONE (branch `gaps/plc-binding`)

**Problem:** a web (OAuth) member's e2ee bundle is signed with a random key, so
a steward accepts any bundle the host serves for that DID. A hostile host can
substitute its own bundle and be sealed the room key.

**Fix:** anchor the binding in the member's own PDS, not the freeq host.
- The web client already has a per-device Ed25519 key (`IndexedDbDeviceKeyStore`)
  published as an `at.freeq.deviceKey` record in the user's PDS.
- Sign the pre-key bundle with that device key (`identitySigningKey`, added in
  f2ac4ad2 for did:key guests), so `signing_key` = the device key.
- `verifyBundleBinding` for `did:plc` (app + bot-kit): accept only when
  `signing_key` is an `at.freeq.deviceKey` read from the DID's PDS (KeyLookup
  source `IdentityRecord`, never `OriginServer`) and `spk_signature` verifies.
- An unbound did:plc bundle is refused, with a reason the steward surfaces.
- Update the trust model + known limitations in `docs/INSTANT-ROOMS.md`.

**Done:** the rule is one SDK function (`verifyBundleBinding`, with
`PdsDeviceKeys` reading device keys straight from the PDS with repository
proofs; the app and bot-kit delegate to it). The SDK signs the bundle with the
device key once it loads it after SASL (`e2ee.useBundleSigningKey`). A refusal
that may pass (record not published yet) schedules steward retries in both the
app and bot-kit. Docs updated.

## 2. Web room secrets in localStorage — DONE (branch `gaps/room-secret-storage`)

**Fix:** keep opened epoch secrets in IndexedDB, encrypted under a
non-extractable AES-GCM key generated in the browser (same pattern as the
device key store). Migrate existing localStorage entries on first read, then
delete them. Fall back to memory only when IndexedDB is unavailable.

**Done:** `freeq-app/src/lib/room-secret-store.ts` (`IndexedDbRoomSecretStore`,
write-through memory mirror, ordered writes, AAD = slot). `rooms.ts` restores
asynchronously before fetching keys; `carryRoomKeys` is async and the room
upgrade waits for it before loading the room. No app path ever cleared these
entries (leave keeps them by design), so `remove()` exists but nothing calls
it yet.

## 3. Pi has no room tool — DONE

Add room actions to pi (create / join by link / read / info / invite / keep /
remove / rotate) using bot-kit's `RoomManager` over the existing connection.

Done in `@freeq/harness-kit` (so any harness on the kit gets it) with a thin
pi tool on top:
- bot-kit `RoomManager` gained `invite()` / `revokeInvites()` and a
  `create({ beforeJoin })` hook.
- harness-kit `rooms.ts`: the `RoomsLike` slice, the default factory over the
  connection's bot, a read buffer, room-target parsing. `FreeqConnection`
  keeps rooms wanted, sends no hello into them, re-enters and stewards held
  rooms on connect, and refuses to send into a room it has no key for.
- `freeq_room` tool (create, join, read, say, info, invite, revoke, keep,
  remove, rotate): schema in `tool.ts`, run by `AgentRuntime.runRoomTool`,
  registered by pi. Reads are framed as data with each sender's tier
  (`frameRoomRead` in `inbound.ts`); live room traffic still goes through
  the tier gate.

## 4. `freeq_say` waits up to 5 s for an echo on every send — DONE

The echo normally arrives in one round trip, so the 5 s only bit when the
server refused the message and no echo was ever coming. Rather than drop the
confirmation (an agent needs to know whether it was heard), `say` now ends
the wait on a refusal numeric (401/403/404/406/477) for that target and
returns `refused: "<server reason>"`. Only a stalled connection runs the
full 5 s. Tests: `freeq-mcp/src/session.test.ts` "say confirmation".

## 5. Publish `@freeq/mcp` — TODO (after #118 merges)

npm has `@freeq/mcp@0.1.0`, `@freeq/sdk@0.1.0`, `@freeq/bot-kit@0.1.0`.
`@freeq/mcp@0.2.0` needs `@freeq/sdk@^0.3.0` and `@freeq/bot-kit@^0.2.0`, so
publish in order: sdk → bot-kit → mcp, from `main` after #118 merges.
Needs `npm login` as `chadfowler` (this machine is not logged in).
Check `npm pack --dry-run` contents and `npx -y @freeq/mcp --help` after.

## 6. PR #118 description — DONE

Refresh: guests can now join with a browser did:key; freeqcc is gone from main;
the gaps above are closed.
