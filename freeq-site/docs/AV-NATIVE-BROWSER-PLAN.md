# AV Native + Browser Plan

**Goal:** Native client and browser can both join the same AV session through the SFU using iroh MoQ.

## Step 1: Redeploy staging with working SFU + port exposure

The SFU auth bug is already fixed (commit 6750e88) but staging hasn't been redeployed.
Also need to expose SFU port (4443 internal → 30443 external) via a Miren node_port on the staging cluster.

- [x] Update SessionIndicator.tsx to use /av/call (same origin, no separate SFU URL)
- [x] Fix Procfile to include --iroh flag (Miren uses Procfile over Dockerfile CMD)
- [x] Move call page + JS assets from av_sfu.rs to web.rs (/av/call, /av/assets/*)
- [x] Bind SFU QUIC (UDP) to web server's $PORT — no separate port needed
- [x] Deploy to the staging cluster
- [x] Verify SFU starts on :3000, call page loads at staging.freeq.at/av/call

## Step 2: Verify browser audio through SFU

- [ ] Open staging.freeq.at in two browsers
- [ ] Start voice session, both join
- [ ] Both click Audio → call page opens via /av/call
- [ ] Verify audio flows between browsers through SFU (via WSS /av/moq)

## Step 3: Refactor native client to connect via MoQ

- [x] Add moq-native + moq-relay + moq-lite + hang deps to freeq-av-client
- [x] New `sfu` subcommand: connect to SFU endpoint via moq_native::Client
- [x] WebSocket transport (WSS) works through Miren's HTTP proxy
- [x] Publish broadcast + subscribe to other broadcasts via MoQ cluster
- [x] TESTED: native client connects, publishes, receives broadcast announcements
- [x] Pipe iroh-live AudioBackend audio → MoQ track frames (LocalBroadcast.consume() → origin)
- [x] Receive + decode remote MoQ audio tracks → play through AudioBackend (RemoteBroadcast)
- [x] TESTED: native↔native audio works through SFU over WebSocket

## Step 4: Wire session to SFU endpoint

- [ ] Server sends SFU endpoint URL (not Room ticket) when session starts
- [ ] Native client uses server-provided SFU address
- [x] **TESTED: native + browser audio works through SFU over WebSocket (2026-04-04)**

## Step 5: Clean up

- [ ] Remove iroh-live Room code from server (av_media.rs)
- [ ] Remove Room-based commands from native client
- [ ] Update docs
