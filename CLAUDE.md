> **⚠️ Pending developer-account work — do not lose track.**
> A batch of signing/distribution tasks for macOS, iOS, and Android is
> **blocked on Apple Developer Program + Google Play Console approval**.
> When those accounts are approved, work through
> **`docs/DEVELOPER-ACCOUNT-TODO.md`** (Developer ID + notarization + Sparkle
> for Mac; Live Activity/Watch provisioning + APNs/CallKit + TestFlight for
> iOS; release keystore + Play App Signing + FCM for Android; plus the
> coordinated S2 session-scoping flip and store-compliance items). The code is
> already ready — these are the identity/provisioning steps ad-hoc signing
> can't do.

**Requirements:**
- `session_id` must be unique per TCP connection
- `nonce` must be cryptographically random
- Timestamp validity window: **≤ 60 seconds**
- Challenge must be invalidated after use

---

### 3.6 Signature Verification

The server must:

1. Resolve the DID document
2. Extract acceptable verification keys
3. Verify the signature over the exact challenge bytes

#### Key Rules

- Accept keys listed under:
  - `authentication`
  - (optional fallback) `assertionMethod`
- Do **not** accept delegation keys
- Supported curves:
  - `secp256k1` (MUST)
  - `ed25519` (SHOULD)

#### Signature Encoding

- Signature is `base64url` (unpadded)
- Signature is over raw challenge bytes
- No hashing unless explicitly required by key type

---

### 3.7 Post-Authentication Behavior

On success:

- Bind the connection to the DID
- Treat the IRC nick as a **display alias**
- Internal account identity = DID
- Emit standard IRC numeric `903`

On failure:

- Emit numeric `904`
- Terminate SASL flow cleanly
- Allow fallback to guest auth

---

### 3.8 Backward Compatibility

- Clients that do not request SASL must still connect
- Clients that do not support `ATPROTO-CHALLENGE` must still connect
- No existing IRC behavior may break

---

## 4. Deliverable B: Minimal TUI Client

### 4.1 Purpose

The client exists to:
- Prove the SASL mechanism works
- Demonstrate a realistic user flow
- Serve as a reference implementation

This is **not** a full IRC client.

---

### 4.2 Base Requirements

- Language: Go **or** Rust
- Runs in a terminal
- Uses a simple text UI (no mouse, no GUI toolkit required)
- Connects to the custom IRC server

---

### 4.3 Client Capabilities

The client must:

- Perform IRC registration
- Negotiate IRCv3 capabilities
- Perform SASL authentication using `ATPROTO-CHALLENGE`
- Join a channel
- Send and receive plain text messages

---

### 4.4 AT Authentication Flow (Client-Side)

The client must:

1. Ask the user for:
   - AT identifier (DID or handle)
2. Resolve handle → DID (if needed)
3. Authenticate to the user’s AT identity provider
   - OAuth or app-password is acceptable
4. Receive server challenge
5. Sign challenge with the user’s private key
6. Send signature via SASL
7. Complete IRC registration

Private keys **must never** be sent to the IRC server.

---

### 4.5 UX Expectations

Minimal but clear:

- Status line showing:
  - connection state
  - authenticated DID
- Clear error messages on auth failure
- No crashes on malformed server responses

---

## 5. Testing & Validation

### 5.1 Required Tests

- Successful auth with valid DID
- Failure on:
  - expired challenge
  - replayed nonce
  - invalid signature
  - unsupported key type
- Connection without SASL still works
- Standard IRC client can connect in guest mode

---

### 5.2 Manual Demo Scenario

Contractor must be able to demonstrate:

1. Start server locally
2. Connect with:
   - a standard IRC client (guest)
   - the custom TUI client (authenticated)
3. Join the same channel
4. Exchange messages

---

## 6. Documentation Deliverables

The contractor must provide:

1. **README**
   - How to build server
   - How to run server
   - How to run client
2. **Protocol Notes**
   - Any deviations or assumptions
3. **Known Limitations**
   - Explicit list

---

## 7. Acceptance Criteria

This project is complete when:

- Server successfully authenticates users via AT-backed SASL
- Client completes full auth flow without hacks
- System behaves as a normal IRC server for non-AT clients
- Code is readable, commented, and auditable
- The implementation could plausibly be referenced in an IRCv3 WG proposal

---

## 8. Philosophy (Context for the Implementer)

This project treats IRC as **infrastructure**, not a product.

The goal is to modernize identity without:
- centralization
- UX regressions
- protocol breakage

If something feels “too clever,” it’s probably wrong.

---

## Hotspot Analysis

Run `./scripts/hotspots.sh` at session start to identify high-risk files. Focus adversarial testing, careful review, and iterative refactoring on files with high gamma scores. Files with low gamma can be changed quickly.

**Current hotspots (updated 2026-03-31):**
- `server.rs` (gamma 334) — heavily tested, 116 unit/integration tests
- `web.rs` (gamma 275) — 41 tests (broker + upload + REST)
- `irc/client.ts` (gamma 133) — **UNDERTESTED** — needs dedicated unit tests
- `MessageList.tsx` (gamma 103) — **UNDERTESTED** — only Playwright coverage
- `sdk/client.rs` (gamma 104) — **ZERO unit tests** on connection state machine
- `store.ts` (gamma 43) — well tested (397 vitest)

When modifying a high-gamma file, write tests FIRST.

---

## TODO

### P0 — Critical (do next)

- [x] **`msgid` on all messages** — ✅ DONE. ULID on every PRIVMSG/NOTICE, carried in IRCv3 `msgid` tag, stored in DB + history, included in CHATHISTORY replay and JOIN history. S2S preserves msgid across federation.
- [x] **Message signing by default** — ✅ DONE (Phase 1 + 1.5). Client-side ed25519 signing with session keys for true non-repudiation. SDK/web/iOS generate per-session ed25519 keypair, register via `MSGSIG`, sign every PRIVMSG with `+freeq.at/sig`. Server verifies client sigs and relays unchanged. Fallback: server signs if client doesn't support signing. Public keys at `/api/v1/signing-key` (server) and `/api/v1/signing-keys/{did}` (per-DID). Web client shows signed badge (🔒).

### P1 — High priority

- [ ] **AV: web call grid auto-layout** — web CallPanel must auto-adjust tile layout for participant counts from 1 to ~30 (macOS already does this via `CallGridLayout.tileSize`; port the same policy to web).
- [ ] **AV: click-to-focus a call tile (ALL clients)** — clicking a participant chip/card focuses it (large tile, others shrink to strip). Web + macOS + iOS.
- [x] **Message editing** — ✅ DONE. `+draft/edit=<msgid>` on PRIVMSG. Server verifies authorship, stores with `replaces_msgid`, updates in-memory history, broadcasts to channel.
- [x] **Message deletion** — ✅ DONE. `+draft/delete=<msgid>` on TAGMSG. Soft delete (deleted_at). Author or ops can delete. Excluded from CHATHISTORY/history.
- [x] **`away-notify` cap** — ✅ DONE. Broadcast AWAY changes to shared channel members. Server, SDK, TUI, and web client all support it.
- [x] **S2S authorization on Kick/Mode** — ✅ DONE. Receiving server verifies the kicker/mode-setter is an op (via remote_members is_op, founder_did, or did_ops) before executing. Unauthorized mode/kick events are rejected with warning log.
- [x] **S2S authorization on Topic** — ✅ DONE. +t channels reject topic changes from non-ops. Removed "trust unknown users" fallback.
- [x] **SyncResponse channel creation limit** — ✅ DONE. `MAX_SYNC_CHANNELS = 500` cap in `server.rs:3116`; overflow truncated with `tracing::warn!`.
- [x] **ChannelCreated should propagate default modes** — ✅ DONE. New channels from S2S get +nt defaults.
- [x] **Invites should sync via S2S** — ✅ DONE. S2sMessage::Invite variant relays invite tokens (DID or nick:XXX) to peers. SyncResponse carries invites (additive merge). S2S Join enforcement checks invite list before rejecting +i. Invites consumed on join.
- [x] **S2S rate limiting** — ✅ DONE. 100 events/sec/peer enforced in `process_s2s_message` (`server.rs:2135`) via `S2S_RATE_LIMITS` map + `S2S_MAX_EVENTS_PER_SEC`. Over-limit events dropped with a single warn-per-second per peer.
- [x] **DPoP nonce retry for SASL verification** — ✅ DONE. Server detects PDS `use_dpop_nonce` errors, sends fresh nonce to client via NOTICE, re-issues SASL challenge. Client (SDK) updates DPoP nonce and retries automatically. Capped at 3 retries per SASL attempt to prevent infinite loops. Counter resets on new SASL attempt.

### P2 — Important

- [x] **Topic merge consistency** — ✅ DONE. Sync-adopted topics now seed the CRDT (only when CRDT has none), making the CRDT the single topic authority. No more dual merge strategies.
- [x] **Channel key removal propagation** — ✅ DONE. With no local members, SyncResponse adopts the full mode snapshot including `key: None` (-k propagates). With locals present, snapshots still never weaken local protections (live S2S Mode events handle -k there).
- [x] **SyncResponse invite authority** — ✅ DONE. Synced invites are only merged when the peer's snapshot names the same founder we have (or we have none); mismatches are rejected + logged. Closes the +i bypass.
- [ ] **S2S authentication (allowlist enforcement)** — `--s2s-allowed-peers` only checks incoming. Formalize mutual auth.
- [x] **Ban sync + enforcement** — ✅ DONE. S2sMessage::Ban variant, authorized set/remove, SyncResponse carries bans, additive merge.
- [x] **S2S Join enforcement** — ✅ DONE. Incoming S2S Joins check bans (nick + DID) and +i (invite only). Blocked joins logged.
- [x] **Hostname cloaking** — ✅ DONE. `freeq/plc/xxxxxxxx` for DID users, `freeq/guest` for guests.
- [x] **IRCv3: account-notify / extended-join** — ✅ DONE. DID broadcast on SASL success and extended JOIN.
- [x] **IRCv3: CHATHISTORY** — ✅ DONE. On-demand history retrieval with batch support.
- [x] **Connection limits** — ✅ DONE. 20 per-IP at TCP + WebSocket level.
- [x] **OPER command** — ✅ DONE. OPER <name> <password> + auto-OPER via --oper-dids. Server opers bypass channel op checks.
- [ ] **TUI auto-reconnection** — Reconnect with backoff, rejoin channels.
- [x] **Normalize nick_to_session to lowercase keys** — ✅ DONE. NickMap wrapper with O(1) bidirectional lookups. All 39 call sites updated.

### P2.5 — Web App Prerequisites (see `docs/WEB-APP-PLAN.md`)

- [x] **Web app (Phase 1)** — ✅ DONE. React+TS+Vite+Tailwind at freeq-app/.
- [x] **Search (FTS5)** — ✅ DONE. SQLite FTS5 index (plaintext DBs; encrypted DBs use bounded decrypt-and-scan, and opening encrypted drops any stale plaintext index). IRC `SEARCH <target> :<query>` with CHATHISTORY-equivalent authorization, results in `freeq.at/search` batch. REST `GET /api/v1/search?channel=&q=` (channels only, +i/+k → 403). 9 db unit tests + 6 acceptance tests.
- [x] **Pinned messages** — ✅ DONE. PIN/UNPIN/PINS commands, REST API, web client PinnedBar + context menu.

### P3 — Future

- [ ] Wire CRDT to live S2S (replace ad-hoc JSON for durable state)
- [ ] DID-based key exchange for E2EE (replace passphrase-based)
- [ ] Full-text search (SQLite FTS5)
- [ ] Bot framework (formalize SDK pattern)
- [ ] AT Protocol record-backed channels
- [ ] Reputation/trust via social graph
- [ ] Serverless P2P mode
- [ ] IRCv3 WG proposal for ATPROTO-CHALLENGE
- [x] Web client — ✅ DONE (freeq-app/, deployed at irc.freeq.at)
- [ ] Moderation event log (CRDT-backed, ULID-keyed)
- [ ] AT Protocol label integration for moderation

### Done (this session)

- [x] Case-insensitive remote_members helpers (`remote_member()`, `has_remote_member()`, `remove_remote_member()`)
- [x] All S2S handlers use case-insensitive nick lookups (Privmsg +n/+m, Part, Quit, NickChange, Mode +o/+v, Kick, Topic)
- [x] SyncResponse mode protection (never weakens local +n/+i/+t/+m)
- [x] Topic flow fix (S2S Topic +t trusts peer authorization for unknown users)
- [x] KICK sending-side case-insensitive remove
- [x] 15 new edge case acceptance tests (96 total, all passing)
- [x] Full S2S sync audit (`docs/SYNC-AUDIT.md`)
- [x] Lint updated to catch raw remote_members access

---

**End of document**
