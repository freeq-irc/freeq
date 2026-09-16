# Changelog

All notable changes to **freeq** — an IRC server, SDK, and client family with AT Protocol identity, S2S federation, and MoQ-based voice/video.

From `v0.9.0-beta.1` onward this project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/). History before the first tag is summarized retroactively by month.

## [Unreleased]

June 2026.

### Added
- Delegated connects: allow an agent to join when it presents a signed `FreeqBotDelegation/v1` certificate that names a permitted owner.
- SASL payload reassembly: the server now joins an `AUTHENTICATE` response split into 400-byte chunks and honours a client-sent `AUTHENTICATE +`, per the IRCv3 base spec.
- FTS5 full-text history search: `SEARCH` command plus REST endpoint backed by SQLite FTS5.
- ATPROTO-CHALLENGE IRCv3 draft specification document.
- `SECURITY.md` security disclosure policy.
- 1.0 / public-beta release plan (one-pager + phased checklist, miren.dev as default self-hosting path).
- claude-mcp agent-kit example: bot bridging Claude Code into a freeq AV call.
- SwiftPM test harness for macOS validation helpers.
- macOS automated UI screenshot sweep script with documented visual-verification findings.

### Changed
- macOS app reached feature parity with web/iOS: voice/video calls, inline media, slash commands, markdown rendering, app icon, pinned-messages bar (via REST), emoji reactions.
- Discord-style voice UX in the web client: persistent call panel and member speaker icons.

### Fixed
- macOS crash paths eliminated, including crash on leaving a call (MoQ session now dropped inside the tokio runtime).
- Black local video preview in web client — replay the moq signal's current value.
- macOS expired-token recovery; "edit/delete last message" no longer targets action/notice lines.

### Security
- Dependency bumps: rmcp 0.8 → 1.7 and openssl 0.10.80 (closes Dependabot alerts 44/45/46).

## [2026-05]

### Added
- `freeq-av` crate: reusable audio/MoQ primitives extracted from the AV stack (AvSession connect/publish/tap loop), plus `freeq-agent-kit` voice-agent helpers and `freeq-av-image` (publish a still image as a video tile).
- `freeq-eliza` (née freeq-transcriber-bot/freeq-utopia): voice agent that transcribes calls, answers spoken Q&A with ElevenLabs TTS, watches participant video, draws whiteboard diagrams, and supports multi-agent dialogue, per-character voices, and pluggable render backends.
- `freeqcc`: Claude-Code-controllable bot daemon with persistent did:key identity, FreeqBotDelegation/v1 provenance certs verified server-side via PROVENANCE, owner-DID gating, streaming replies, and capability-scoped delegation.
- `@freeq/bot-kit` TypeScript package: FreeqBot class, createDaemonCLI, createDidMap, resolveSenderDid, checkMention, createTurnGate; freeqcc migrated onto it.
- `draft/multiline` server capability: BATCH state machine, channel/DM/S2S/CHATHISTORY/JOIN-replay support, BATCH-wrapped multi-line edits, SDK auto-routing on `\n` across Rust/JS/FFI clients.
- `+I` invite-exception list mode; commit-reveal hash binding verification on PRIVMSG.
- TypeScript SDK parity work: 34 new methods, 6 inbound events, agent-protocol surface, comprehensive unit tests.
- iOS/web AV video: real camera capture via Swift, remote video decode, device pickers, full-screen call panel, per-device instance suffix so one DID can join from multiple clients.

### Changed
- Web client connects to the SFU over WebTransport/QUIC (with wss fallback path fixes); jitter/latency budgets trimmed for 1:1 calls.
- Deterministic derived nicks for authenticated nick collisions; LOGIN/OAuth identity binds persisted and owner-gated.
- iOS: channels/DMs persisted to disk for cold-launch context, root UI decoupled from connection state, proactive web-token refresh.

### Fixed
- Android auth recovery: Guest-rename/persistent-401 recovery, WS→TCP transport fallback, kill+restart reconnects as the registered DID user.
- Unified iroh Router so iroh-live no longer stomps freeq ALPNs; phantom session sweeper; nick_to_session self-healing.
- Broker hardening: hard timeouts on /auth/login upstream calls, DPoP-nonce PAR retry handling.
- AV: orphan participant slot reaping, per-instance disconnect cleanup, stale MoQ JS bundle rebuild.

### Security
- freeqcc security audit landed: 2 HIGH, 5 MED, 5 LOW findings fixed.
- Patched 21 of 23 Dependabot alerts across Rust/npm/pip.

## [2026-04]

### Added
- AV sessions (voice/video): session manager + DB schema, IRC TAGMSG control plane, REST APIs, S2S federation, transcript/summary pipeline, and web UI (SessionIndicator, SessionHistory, ArtifactViewer, inline call panel).
- MoQ SFU media transport: embedded SFU serving a browser call page, WebSocket MoQ transport, bidirectional MoQ↔iroh-live bridge — native + browser audio through the SFU confirmed working Apr 4, end-to-end AV calls in channels.
- Native AV client (`freeq-av-client`) with server/join/SFU modes.
- iOS AV: FFI layer (FreeqAv), CallView UI, voice session integration.
- Agent Assistance Interface: validate/diagnose endpoints, pluggable LLM layer, six bot-developer diagnostic tools, API-BEARER NOTICE bridging SASL to tool auth.
- TypeScript SDK extracted from the web app (`@freeq/sdk`) with did:key SASL; logger-bot and karma-bot reference examples.
- IRCv3 `account-tag` (`account=<did>`) on PRIVMSG/NOTICE, used for avatar resolution across all clients.
- Reaction and pin persistence in DB; S2S federation for reactions, pins, DMs, and agent actor_class.
- Emoji reaction removal across server, SDK, and web app.
- WinUI client reached parity with web.

### Changed
- Default OAuth scope narrowed with a per-feature step-up flow (blob upload requests scope on demand).
- WebRTC audio path replaced by MoQ SFU; AV architecture docs rewritten to match the implementation.
- Deploys: cargo-chef Docker dependency caching (~5 min deploys); git commit exposed on all deployed services.

### Fixed
- SDK tears down on SASL 904 instead of silently registering as guest; four more stale-state wire-vs-cache holes closed.
- CHATHISTORY sort-merged into live messages to preserve ordering in the web app.
- DM S2S relay deadlock; local DMs relayed via S2S for cross-server visibility.
- iOS durability: WebSocket transport with 10s connect timeout, durable auth, connect-loop unblock when the broker DB is wiped.

### Security
- Three CTF-style adversarial rounds: agent_assist (5 vulns), OAuth (SSRF chain in /auth/login + /auth/step-up, callback XSS), protocol (pre-key hijacking, +E bypass, TAGMSG flood) — all fixed.
- Adversarial sweep + 6 deploy-readiness fixes for OAuth scope narrowing.

## [2026-03]

### Added
- DM CHATHISTORY: server-side support, `CHATHISTORY TARGETS` conversation discovery across SDK, web, iOS, Android, and TUI.
- Multi-line messages sent as a single message; markdown messages via `+freeq.at/mime=text/markdown` with a compose toggle.
- `LOGIN` command: browser-based AT Protocol auth for legacy IRC clients.
- Agent-native platform (Phases 1–5): did:key agent identity with freeq-bot-id, provenance/presence/heartbeat, governable agents, coordinated work, interop/spawning, economic controls; agent badges, WHOIS/REST/web UI for spawned agents; streaming messages via edit-message.
- Native macOS app: from Phase 1 scaffold to 58/60 feature-gap items closed (avatars, profiles, threads, E2EE, local SQLite message DB, media rendering, search).
- Real-time pin sync via IRCv3 tags across web, iOS, and Android.
- Hotspot analysis script (`scripts/hotspots.sh`) baked into the development workflow.

### Changed
- Join/part/quit noise hidden by default (later: showJoinPart defaulted back on for situational awareness).
- iOS/Android keep broker sessions for a minimum 14-day login window.
- Web-token TTL reduced from 30 minutes to 5 minutes.

### Fixed
- Member-list correctness: multi-prefix NAMES parsing, JOIN clobbering op status, MODE +o arriving before NAMES, NickMap multi-device visibility.
- Ghost session leak causing missed JOIN broadcasts; DM edit storage and DM buffer creation race.
- Three deadlocks in agent broadcast paths (account-notify, cap_message_tags double-lock, AGENT/PRESENCE lock contention).
- Android session persistence, CHATHISTORY pagination, and auto-reconnect on relaunch.
- ~46 bugs total fixed during the testing/audit push, ending at 1420 tests with 0 failures (adversarial suites for SASL, S2S, edit/delete, CHATHISTORY, E2EE, broker auth, plus 397 web client unit tests).

### Security
- Pre-release security audit: 28 vulnerabilities patched across two rounds, with a published audit report.
- HMAC replay prevention (`X-Broker-Timestamp` required), secret files written 0600, encryption-at-rest failures made hard errors.
- REST history restricted for invite-only/keyed channels; DID-based authorship checks on edit/delete; S2S field sanitization against IRC protocol injection.
- Per-IP rate limiting on REST proxy/upload endpoints; channel name/topic length limits.

## [2026-02]

### Added
- Initial release: IRC server, Rust SDK, and TUI client with AT Protocol SASL authentication (ATPROTO-CHALLENGE), rich media via IRCv3 tags, reactions, link previews, and rich WHOIS profiles.
- iroh transport: P2P DMs, S2S server clustering with Automerge CRDT state, DID-based persistent channel ops, federation of identity/modes/topics across servers.
- E2EE: encrypted channels, then Double Ratchet + X3DH DMs (+E mode), client-side ed25519 message signing with session keys, encryption at rest for SQLite messages.
- IRCv3 surface: CHATHISTORY, account-notify, extended-join, away-notify, echo-message, msgid (ULID on every message), message editing/deletion via draft tags.
- Web clients: freeq-web prototype, then freeq-app (React + TS + Vite + Tailwind) with OAuth login, threads, search, PWA, Playwright E2E suite; deployed at irc.freeq.at.
- Native apps: iOS (SwiftUI + Rust SDK via UniFFI), Android (Jetpack Compose + Material 3), Windows desktop client, Tauri desktop build.
- Policy & Authority Framework: channel join gates, verifiable credentials with external issuers (GitHub org/repo, Bluesky follower gate), moderation framework with halfop and credential-based moderators.
- Auth broker service for persistent web sessions; pi IRC bridge; freeq-bots AI agent platform; pinned messages (PIN/UNPIN/PINS + REST).
- freeq.at website (Flask + markdown docs) and docs overhaul; Docker + CI.

### Changed
- Project rebranded to **freeq** (Feb 12).
- Internal identity is the DID; nicks are display aliases with hostname cloaking (`freeq/plc/xxxxxxxx`, `freeq/guest`).
- Multi-device support: same DID, same nick, simultaneous sessions; nick_to_session normalized via O(1) NickMap.

### Fixed
- Long tail of S2S federation fixes: split-brain ops races, broadcast ordering through a single queue, duplicate-connection death loop, case-insensitive nick/channel lookups, ghost cleanup, asymmetric PM relay.
- OAuth flow stabilization: DPoP nonce retry, RFC 8252 loopback compliance, popup/same-window flows, broker return_to handling.
- Ghost connection cleanup: WebSocket send timeouts, QUIT on tab close, same-DID session reclaim with history preserved.

### Security
- Pre-launch hardening: XSS sanitization, per-IP connection limits, rate limiting, upload auth, SSRF protections, replay prevention, token cleanup, security headers, TLS certs removed from the repo.
- S2S auth lockdown: peer allowlist required when peering; S2S authorization on Mode/Kick/Topic; ban sync and Join enforcement; S2S rate limiting.
- Server-side OG proxy replacing a third-party privacy leak.
