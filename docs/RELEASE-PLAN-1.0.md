# freeq 1.0 / Public Beta Release Plan

_Last updated: 2026-06-11 (evening sprint — search, ghost-session fix, federation
fixes, metrics, permalinks/export, oauth tests, Miren path, governance docs,
IRCv3 draft, CI audit all landed; tagged v0.9.0-beta.1)._

## One-pager: what freeq is and why it matters

**freeq is an open, federated, agent-native communication substrate.** It takes
IRC — the only chat protocol that ever achieved true openness — and rebuilds it
for the present: AT Protocol (Bluesky) identity via a custom SASL mechanism
(`ATPROTO-CHALLENGE`), ed25519 message signing on every message, E2EE channels
and DMs (X3DH + Double Ratchet), server-to-server federation over iroh QUIC with
CRDT-converged state, voice/video over MoQ, and a first-class agent protocol:
cryptographic `did:key` identities, provenance certificates, governance
(pause/resume/revoke/budget), task coordination events, and agent spawning.

Clients: web (live at irc.freeq.at), iOS, macOS, Android, TUI — plus SDKs in
Rust and TypeScript, a bot-kit, and an agent-kit that bridges Claude Code into
live AV calls. Any legacy IRC client still connects in guest mode.

**Why it's impactful — three claims:**

1. **Slack and Discord are closed silos at exactly the moment conversation
   became the primary artifact of work.** "The conversation is the commit": when
   agents write the code, the human↔agent conversation *is* the engineering
   record. That record cannot live in a proprietary database with ephemeral
   retention and API rate limits. freeq makes conversations durable, signed,
   queryable, and owned by their participants — every message has a ULID msgid,
   a cryptographic signature, and a DID-bound author. Code history becomes
   decision history.

2. **Agents are second-class citizens everywhere else; here they are
   first-class.** On Slack/Discord a bot is an API token. On freeq an agent has
   a self-certifying DID, a provenance cert declaring who built it and on whose
   authority, governable lifecycle, budget controls, presence, and — via
   eliza/ghostly/revenant — a face, a voice, and persistent memory keyed to the
   DIDs of everyone it meets. Revenant demonstrates the category shift: an agent
   that sleeps for ~$0, wakes on summon in ~160ms, and remembers your last
   conversation. That is not a chatbot; it's a colleague with continuity.

3. **Open protocol + identity portability breaks the network-effect lock.**
   Identity is your AT Protocol DID, not an account in someone's database. Bans,
   ops, and reputation follow the DID across servers. Anyone can self-host and
   federate; the protocol is documented and IRCv3-compatible; the apps aim to be
   *better* than the closed equivalents, not a compromise you accept for
   ideology.

**Current state (honest):** ~1,230 commits in 4 months, 1,420 passing tests, a
46-bug security audit completed in March, live multi-month deployment, feature
parity across web/iOS/macOS, working voice/video, and two flagship agent
demos (freeq-cc, revenant). The protocol and server are 1.0-grade. The gaps are
distribution, search, abuse-handling, notifications, and federation trust — the
things that only matter once strangers show up. Which is the point of a beta.

---

## Release strategy

Three audiences, one beta:

- **Developers** → SDKs/bot-kit/agent-kit published with versions, quickstarts, examples.
- **Self-hosters** → one-command deploy, backups, migrations, metrics, federation that's safe to open.
- **Public network users** → irc.freeq.at + web app + TestFlight, with search, push, and moderation.

Suggested sequence: **Beta blockers → public beta announcement → fast-follows → 1.0 gate.**

## Phase 0 — Release engineering (prerequisite for everything)

- [x] Adopt semver; tag `v0.9.0-beta.1` (local tag created 2026-06-11; push when ready)
- [x] CHANGELOG.md generated from history (2026-06-11); release notes discipline going forward
- [ ] GitHub Releases with prebuilt server binaries (linux x86_64/arm64, macOS)
- [ ] Docker image published to a registry (GHCR), pinned tags, `latest` = stable
- [ ] Publish `freeq-sdk` (Rust) to crates.io; pin/publish `@freeq/sdk`, `@freeq/bot-kit` versions on npm
- [ ] Homebrew formula for freeq-tui (and server)
- [ ] DB schema migration story: versioned migrations + tested upgrade path between releases (self-hosters will upgrade; today there is no documented path)

## Phase 1 — Public beta blockers

### Product credibility (Slack/Discord-replacement table stakes)
- [x] **Search (FTS5) — server side DONE** (2026-06-11). FTS5 index + IRC SEARCH command + REST /api/v1/search, CHATHISTORY-grade authorization, 15 new tests. Remaining: surface in web/macOS/iOS clients; land `fix/eliza-recall-or-semantics` for agent memory recall
- [ ] **Real push notifications** — web push via service worker (currently only while tab open); APNs for iOS/macOS; FCM for Android. A team chat tool without notifications when closed is unusable as a daily driver
- [x] **Message permalinks + export — server side DONE** (2026-06-11). GET /api/v1/messages/{msgid} + /api/v1/channels/{name}/export?format=json|markdown. Remaining: web client deep-link route + export button
- [ ] Web client offline/reconnect resilience pass (it has IndexedDB + SW; verify the disconnect/resume path under real network churn)

### Abuse & moderation (the public-network killer)
- [ ] Server-level admin tooling: oper commands to freeze/quarantine channels, shadow-limit guests, global DID ban
- [ ] Guest abuse posture: decide registration requirements for channel creation / DM initiation on the public network (DID-required is a reasonable default)
- [ ] Report flow (even minimal: /report → oper queue)
- [ ] Terms of service + moderation policy for irc.freeq.at; Code of Conduct in repo
- [ ] Moderation event log (CRDT, ULID-keyed) — at least the schema + append path, so beta moderation actions are auditable from day one

### Federation safety (strangers will federate during beta)
- [ ] **S2S mutual auth** — formalize: both directions check allowlist; document trust levels (Readonly/Relay/Full) and make them configurable per peer
- [x] Fix topic merge flapping — DONE 2026-06-11 (sync-adopted topics seed the CRDT; CRDT is sole topic authority)
- [x] Channel key removal (`-k`) propagation — DONE 2026-06-11 (full snapshot adoption when no local members)
- [x] SyncResponse invite merge founder-authority check — DONE 2026-06-11 (founder mismatch → invites rejected + logged)
- [ ] Federation operator guide: how to peer with the public network, what state you accept, how to de-peer

### Agent platform fixes (before pushing agent developers)
- [x] **Ghost session bug** — DONE 2026-06-11. Liveness probe on same-DID attach: siblings that don't PONG within 10s are evicted via normal cleanup (~10s instead of ~90s); healthy multi-device clients unaffected
- [x] Audit items — DONE 2026-06-11. ConnectConfig::validate() now actually enforced in establish_connection (+5 tests); typing auto-clear and backgroundWhois cap verified already implemented
- [ ] Agent developer quickstart: "bot in 5 minutes" + "governed agent in 30" using bot-kit/agent-kit; publish freeq-cc as the Claude Code agent reference

### Self-hosting story — **miren.dev is the default path**
- [x] Miren template — DONE 2026-06-11 (deploy/miren/: parameterized deploy.sh + Dockerfile + 10-min README; runs from a fresh clone). Remaining: verify the TODO(verify) Miren CLI specifics against a real Miren instance, then test as a stranger
- [x] `docs/self-hosting.md` leads with Miren — DONE 2026-06-11 (also fixed broken `--bind` flag in docker-compose; added `--bind` alias to server)
- [ ] Smoke-test the Miren path end to end as a stranger would (fresh account, fresh domain, federate with irc.freeq.at)
- [x] **Backup/restore documentation** — DONE 2026-06-11 (deploy/miren/README.md: sqlite3 .backup / VACUUM INTO, WAL/SHM + *.secret notes)
- [x] Prometheus `/metrics` endpoint — DONE 2026-06-11 (connections/channels/s2s_peers gauges; messages, sasl success/failure counters; uptime)
- [ ] Upgrade procedure doc tied to the migration story in Phase 0 (Miren redeploy + migration path included)

### Security posture
- [x] SECURITY.md + responsible disclosure policy — DONE 2026-06-11
- [x] `cargo audit` + `npm audit` in CI — DONE 2026-06-11 (3 documented transitive exceptions in .cargo/audit.toml; npm clean)
- [x] oauth.rs unit tests (mock PDS) — DONE 2026-06-11 (38 tests: DPoP nonce dance, bounded retries, DID mismatch, callback CSRF, encrypted session persistence). Residual: client-side login() lacks HTTPS-only PDS URL check
- [ ] Key rotation: invalidate sessions when DID doc keys change (known limitation; matters more at public scale)

## Phase 2 — Beta launch

- [ ] iOS + macOS: public TestFlight links (privacy policy, App Store metadata prep)
- [ ] freeq.at site refresh: positioning per the one-pager, three audience funnels (use it / build on it / host it), docs reorganized for outsiders
- [ ] Announce: blog post pairing the launch with "The Conversation Is the Commit"; Bluesky-native launch (the identity layer *is* Bluesky — lean in)
- [ ] Seed the network: #freeq, #agents, #dev channels; run revenant personas publicly as the demo
- [ ] Status page + alerting for irc.freeq.at
- [ ] Feedback channel + triage cadence

## Phase 3 — 1.0 gate (after beta feedback)

- [ ] App Store / Play Store submissions (iOS, macOS; Android after small-screen polish)
- [~] ATPROTO-CHALLENGE IRCv3 WG draft — spec WRITTEN 2026-06-11 (docs/ircv3/atproto-challenge.md, WG house style, crypto method normative, byte-accurate examples). Editor's notes list implementation divergences to fix before submission: AUTHENTICATE 400-byte chunking not implemented anywhere, no server-name binding in challenge, abort returns 904 not 906, bare `sasl` cap (no 302 mechanism list). Remaining: fix those, open ircv3-specifications issue → PR, offer Ergo second implementation, IANA registration later
- [ ] Second security review (external if possible) focused on federation + agent surfaces
- [ ] Conversation↔artifact linking: msgid trailers in git commits / freeq-cc emitting commit↔conversation links (thesis feature, scope after beta learnings)
- [ ] TUI auto-reconnect
- [ ] sdk/client.rs connection state machine tests; irc/client.ts + MessageList.tsx unit tests (known undertested hotspots)
- [ ] Scale review of single-SQLite public server; document limits, plan sharding/read-replicas only if beta demand requires

## Explicitly deferred past 1.0

- Windows native app (design phase; web covers Windows)
- Screen share; browser P2P (iroh-live) rooms
- DID-based E2EE key exchange replacing passphrases; channel forward secrecy
- AT Protocol record-backed channels; label-based moderation integration
- Serverless P2P mode; reputation via social graph
- ghostly GPU backend / FFT audio bands / composite mode (revenant track, not core)

## Needs Chad (credentials / outward-facing — not automatable)

- [ ] Push main + the `v0.9.0-beta.1` tag to GitHub; create the GitHub Release
- [ ] Publish: `freeq-sdk` to crates.io; version-bump + publish `@freeq/sdk`, `@freeq/bot-kit` on npm; Docker image to GHCR
- [ ] Verify deploy/miren TODO(verify) items against a real Miren instance, then run the stranger test (fresh account → own domain → federate with irc.freeq.at)
- [ ] Publish PGP key for security@freeq.at (SECURITY.md references it); set up security@ + conduct@ mailboxes
- [ ] TestFlight public links (iOS/macOS); App Store metadata + privacy policy
- [ ] Deploy current main to irc.freeq.at (picks up search, liveness eviction, federation fixes, /metrics)
- [ ] Decide launch timing; pair announcement with "The Conversation Is the Commit"

## What is already done (do not redo)

Protocol core, SASL/identity, signing, msgid, edit/delete/reactions/threads/pins,
CHATHISTORY, E2EE (channels + DM ratchet), S2S with CRDT + authz + rate limits,
agent phases 1–5 (identity/governance/tasks/spawning/economics), AV SFU
(voice+video, web+native), 46-bug security audit, 1,420 tests, CI, live
deployment, deploy scripts, Docker, web client at parity, iOS/macOS at parity.
