# Instant rooms: closing the known gaps (PR #118)

Started 2026-11-05. Branch: `instant-rooms`. Updated as work lands.

The gaps come from the PR's "Known limitations" and `docs/INSTANT-ROOMS.md`.

## 1. `did:plc` pre-key bundles are not bound to the DID — TODO

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

## 3. Pi has no room tool — TODO

Add room actions to pi (create / join by link / read / info / invite / keep /
remove / rotate) using bot-kit's `RoomManager` over the existing connection.

## 4. `freeq_say` waits up to 5 s for an echo on every send — TODO

Wait for the echo only where it matters: one-shot CLI runs (process exits
after the send) and room sends. A long-lived MCP server returns at once.

## 5. Publish `@freeq/mcp` — TODO (after #118 merges)

npm has `@freeq/mcp@0.1.0`, `@freeq/sdk@0.1.0`, `@freeq/bot-kit@0.1.0`.
`@freeq/mcp@0.2.0` needs `@freeq/sdk@^0.3.0` and `@freeq/bot-kit@^0.2.0`, so
publish in order: sdk → bot-kit → mcp, from `main` after #118 merges.
Needs `npm login` as `chadfowler` (this machine is not logged in).
Check `npm pack --dry-run` contents and `npx -y @freeq/mcp --help` after.

## 6. PR #118 description — TODO

Refresh: guests can now join with a browser did:key; freeqcc is gone from main;
the gaps above are closed.
