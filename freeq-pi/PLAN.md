# @freeq/pi — implementation plan

Living document. Updated as work proceeds. Spec: `docs/PI-FREEQ-BUILD-SPEC.md`.
Design: `docs/PI-FREEQ-MULTIPLAYER.md`. Pitch: `docs/PI-FREEQ-PITCH.md`.

## Status

| milestone | state | notes |
|---|---|---|
| M0 — headless spike bot | **DONE** ✅ | proved live on `#playground` — see evidence below |
| M1 — package skeleton | **DONE** ✅ | two installs mutually visible w/ metadata + DIDs |
| M2 — tool + tiered inbound | **DONE** ✅ | cross-agent ask verified; tier gate holds |
| M3 — humans in the room | **DONE** ✅ | Demo 2 verified: human → agent → answer in room |
| M4 — handoffs | **DONE** ✅ | offer→accept→complete survives BOTH sides offline |

## Reading list — done

- [x] `docs/PI-FREEQ-PITCH.md`, `docs/PI-FREEQ-MULTIPLAYER.md`, `docs/PI-FREEQ-BUILD-SPEC.md`
- [x] pi `docs/extensions.md` (sendUserMessage/registerTool/registerCommand/ctx.isIdle/ctx.ui)
- [x] pi `docs/packages.md` (`"pi"` key, install sources), `docs/skills.md`, `docs/sdk.md`
- [x] `freeq-sdk-js/src/client.ts` + `events.ts` + `types.ts`
- [x] `freeq-bot-kit-js/src/bot.ts` + `identity.ts`, `examples/echo-bot.ts`
- [x] `docs/agent-quickstart.md`

## Key API facts confirmed (grounding for implementation)

**pi side**
- `pi.sendUserMessage(content, { deliverAs })` — `deliverAs` **required while
  streaming** (`"steer"` | `"followUp"`), throws if streaming without it;
  immediate + triggers turn when idle. This is the inbound primitive.
- `pi.registerTool({ name, label, description, parameters: TypeBox, execute })`.
- `pi.registerCommand(name, { description, handler })`.
- `ctx.isIdle()`, `ctx.ui.notify/confirm/select/input`, `ctx.cwd`,
  `ctx.isProjectTrusted()`, `CONFIG_DIR_NAME` (don't hardcode `.pi`).
- Events: `session_start`, `session_shutdown`, `agent_settled`, `tool_call`,
  `tool_result`, `turn_end`.
- Package manifest: `"pi": { "extensions": ["./extensions"], "skills": ["./skills"] }`.

**freeq side**
- `FreeqBot.create({ name, ownerDid, nick, url, channels, actorClass,
  initialState, initialStatus, manifest, heartbeatMs, creatorKeyPath, ... })`
  → mints/loads `did:key` under `~/.freeq/bots/<name>/`, delegation cert,
  SASL crypto auth, AGENT REGISTER + heartbeats.
- `bot.client` is a `FreeqClient`: `sendMessage(target, text)`,
  `sendTagmsg(target, tags)`, `join`, `joinMany`, `quit`, `on(event, h)`.
- `bot.on(...)` proxies to client. `bot.resolveSenderDid(...)` → sender DID
  (needed for authority tiers). `bot.checkMention(channel, text)` for
  addressed mode.
- `Message` has `{ id, from, text, tags: Record<string,string>, isSelf, ... }`
  — **`tags` gives us the ask correlation IDs.**
- Presence/status: bot-kit heartbeats carry state/status → M1 presence rides
  this, plus `AGENT MANIFEST`.

## Decisions made during implementation

1. **Spike (M0) uses `FreeqBot` + pi `createAgentSession`** rather than a raw
   client — bot-kit already does identity/delegation/heartbeat correctly.
2. **Ask correlation tags:** `+freeq.at/pi-req=<ulid>` on the question,
   `+freeq.at/pi-res=<ulid>` on the answer. Vendor-namespaced, ride
   `sendTagmsg`/message tags. Not dependent on `+draft/reply`.
3. **Identity naming:** bot-kit `name` = `pi-<install-slug>`, so state lands in
   `~/.freeq/bots/pi-<slug>/` reusing bot-kit's persistence rather than
   inventing `~/.freeq/pi/`. (Spec said `~/.freeq/pi/identity/`; this is the
   same intent with less new code — flagged as a deviation, see below.)

## M1 evidence (acceptance met)

Acceptance: *"two machines run pi with the package; `/freeq peers` on each
shows the other with live session metadata."* Verified against a **local**
freeq-server (see "prod hygiene" below) with two independent installation
identities and separate state roots — the same shape as two laptops:

```
alice: online: pi-alice-z6mkkzxf (did:key:z6MkkZXFr1Tz…)
bob:   online: pi-bob-z6mkhx5r  (did:key:z6Mkhx5r2Cs7…)
alice → pi-bob-z6mkhx5r   [did:key:z6Mkhx5r…] online freeq @main (github.com/…) · test-model
bob   → pi-alice-z6mkkzxf [did:key:z6MkkZXF…] online freeq @main (github.com/…) · test-model
```

Harness: `spike/peers-check.ts` (exit 0 = acceptance). 32 unit tests pass.
Extension verified to load in real pi (`pi -e … --mode rpc`) without
disturbing a normal session.

## ⚠️ Finding: presence cannot carry metadata (design change, no server change)

First M1 run showed peers as `no metadata`. Root cause is in the **server**,
not our code — `freeq-server/src/connection/mod.rs` relays PRESENCE to peers
over the IRC `AWAY` back-compat mechanism, and "back from away" is
parameterless by IRC semantics:

```rust
let is_clear = ps == Online || ps == Active || ps == Idle;
let line = if is_clear { ":{hostmask} AWAY" }          // status DROPPED
           else        { ":{hostmask} AWAY :{away_text}" };
```

So an **active** agent can never advertise session metadata via PRESENCE
status — status only propagates for away-ish states. Options were (a) lie
about liveness to smuggle status, (b) change the server, (c) move discovery
to an application-level announcement. Took **(c)**:

- `src/discovery.ts` — `pi_hello` / `pi_hello_ack` over the existing
  `+freeq.at/event=*` coordination-event channel (TAGMSG). The SDK already
  parses it, de-dupes by event id, and annotates the sender's DID.
- No server change; richer structured JSON instead of a squeezed status line;
  and it's the same TAGMSG substrate M2's `ask` needs anyway.
- Ack storms avoided: we reply to `hello`, never to `hello_ack`.
- **Security:** the `did` inside a hello is self-asserted and is never used
  for authorization — peer DIDs come from the SDK's server-backed resolution.
  Unit-tested; M2's tier decisions depend on this distinction.

Presence is still sent (liveness + any client that can read status); hellos
are what peers actually learn metadata from.

**Recommend filing a freeq-server issue** (not doing it under this contract):
relaying presence status for active agents needs a real mechanism rather than
the AWAY back-compat path. Not blocking — discovery no longer depends on it.

## Prod hygiene (changed after M0)

M0 ran against **production** `irc.freeq.at` and left two permanent messages
in public `#playground` history — including an agent answer containing an
absolute local path (`/Users/chad/src/freeq`). Presence is now hardened
against path leaks (`looksLikePath`, unit-tested), but the **answer** path
isn't yet — M3's scrubber must redact absolute paths, not just secrets.
Scope updated below.

All M1 work ran against a **local** server:

```
target/release/freeq-server --listen-addr 127.0.0.1:16667 \
  --web-addr 127.0.0.1:18080 --db-path /tmp/freeq-local/test.db
```

Dev stays local from here; prod is reserved for the recorded demo.

## M2 evidence (core capability proven)

Harness `spike/ask-check.ts` stands up **two independent pi sessions**, each
with its own installation identity, own freeq connection, and own working
directory. The responder's cwd contains a fact the asker cannot see.

```
[m2] TEST 1 — ask from an UNTRUSTED peer (must be declined)
[responder] ask from pi-asker tier=observe → surface (needs 'request')
[m2] ✓ declined as expected

[m2] TEST 2 — same ask after granting 'request' tier
[responder] ask from pi-asker tier=request → answer
[m2] ✓ answer: SHIPPING-VALVE-7731
[m2] ✓ contains SHIPPING-VALVE-7731 — knowledge crossed the network
```

The same question is **refused before trust and answered after** — the tier
gate is load-bearing, not decorative. 65 unit tests pass, including the
mandatory invariant across all 24 kind×mode×addressed×DID combinations.

Tool registration verified in a real pi session (`--mode rpc`): the model
discovered `freeq`, called it with `{action:"peers"}`, and got the graceful
unconfigured message.

**Still outstanding for the real v0.1 criterion:** two people, two laptops,
across the internet, recorded. The harness proves the mechanism; it cannot
prove the human/organisational half.

## M2 design decisions

1. **`ask` rides coordination events**, like discovery — `pi_ask` /
   `pi_ask_reply` with a caller-minted request id in the payload. No
   dependence on IRC reply tags, per the design doc's Decided section.
2. **Payload sizing measures the encoded form.** The server line limit is 8192
   incl. tags and percent-encoding can triple non-ASCII text, so `encodePayload`
   shrinks until the *encoded* string fits (raw-length budgeting would
   overshoot; unit-tested with emoji).
3. **Answer hijacking is blocked**: a reply is only accepted from the peer we
   asked. A third party answering someone else's question is dropped and
   reported.
4. **Declines are explicit.** An ask that fails the tier gate gets a
   `declined: <reason>` reply rather than silence — silence is
   indistinguishable from a broken agent, and would burn the asker's timeout.
5. **One injection point.** `deliver()` in the extension is the only function
   that calls `pi.sendUserMessage`, and it refuses unless `decideInbound`
   returned `inject`/`answer`. `src/inbound.ts` is pure, so the policy is
   testable without any I/O.
6. **`/freeq trust` requires confirmation** and spells out that `request`+
   lets a peer trigger turns in your session.

## Deviations from spec (flagged for review)

- **Identity storage path**: using bot-kit's `~/.freeq/bots/pi-<slug>/`
  instead of a new `~/.freeq/pi/identity/`. Rationale: reuse
  `loadOrCreateIdentity` + delegation minting exactly as bot-kit does it; no
  new persistence code. Behaviour (one owner-bound `did:key` per
  installation, 0600) is unchanged. Revert if you want the distinct path.

## M3 evidence (first release complete)

Harness `spike/room-check.ts` — a DID-authenticated **human** on a plain freeq
client (no pi) in a channel with an agent:

```
TEST 1 — unaddressed chatter        → surface        ✓ agent stayed quiet
TEST 2 — addressed, untrusted human → surface        ✓ declined to answer
TEST 3 — addressed, 'message' tier  → inject
  ✓ answered in the room: "Staging build tag: PELICAN-4402"
  ✓ contains PELICAN-4402 — from its own environment
```

90 unit tests. All three live harnesses pass (`npm run verify`).

### Bug found by the M3 harness (product fix, not a test fix)

The server auto-suffixes nicks on collision (`pi-agent` → `pi-agent-z6mkher4`).
A human addressing the **configured** nick then failed to match, so the agent
silently stopped answering to the name its teammates were told. Fixed with a
custom mention matcher that matches the live nick **and** the configured one.
This would have been a confusing intermittent failure in a live demo.

### M3 scope delivered

- `src/scrub.ts` — central outbound redaction for secrets **and absolute
  paths** (the M0 leak class), enforced in `FreeqConnection` so no send path
  can bypass it. Regression test uses the verbatim M0 leak.
- Channel replies (Demo 2): addressed messages get answered in the room,
  truncated to chat size, with bot-kit's per-channel cooldown preventing
  two agents from ping-ponging.
- `/freeq mute` / `unmute` — stay connected and reachable but say nothing.
- Batched OBSERVE notifications (one grouped notice per 4s, not one per line).
- `DEMO.md` — solo verification + the two-laptop demo script + recording
  checklist.

## M4 evidence — handoffs survive offline

`spike/handoff-check.ts`, run against **production** (see note on the local
server below). The test is deliberately harsh: nobody is online to relay
anything.

```
STEP 1  bob is offline (never started)
        ✓ alice offered task 01M130ZXXK to an OFFLINE recipient
STEP 2  alice disconnects — nothing is running anywhere
STEP 3  bob starts for the first time
        ✓ bob learned about the offer from replay (fromReplay=true)
        ✓ it shows in bob's inbox
STEP 4  bob accepts and completes
STEP 5  alice reconnects with an EMPTY view
        ✓ alice sees the task COMPLETED
        ✓ signed lifecycle replayed: offer → accept → complete
        ✓ every event in the chain carried a signature
```

Alice's final view was rebuilt entirely from channel history — the RFC's
"signed log is the source of truth, the view is rebuildable" property, working.

### What was reused rather than rebuilt

Per the RFC's build discipline: `sendAct()`/`actTags()` (SDK) sign and emit;
`checkTransition()`/`initialState()` (bot-kit, driven by
`act-transitions.json`) own legality and authority. This package restates
none of those rules — which is why "a third party cannot accept work offered
to someone else" and "only the assignee may complete" passed on the first
run. New here: a persisted local view, and the policy for what a pi session
*does* about an offer.

### Two real bugs found by the M4 harness

1. **Own act events were filtered out.** Chat filters self-echo; act events
   must not. The echo of your own `accept` is what advances your local state
   — with it dropped, an assignee could never reach `complete` — and replay
   of your own offers is how a lost view is rebuilt. Both broken, both fixed.
2. **`sendAct` raced the signing key.** The session key is minted during SASL
   and registered on 001, and `sendAct` signs directly instead of going
   through the SDK's gated send queue, so an offer sent right after connect
   failed with "a task event must be signed". Now waits for the key.

Also: server `confirm` receipts are expected wire traffic, not rejected
transitions. `ApplyResult.benign` distinguishes routine (receipts, duplicate
echoes) from genuine refusals, so the TUI stays quiet about the former.

### Environment findings — RESOLVED

The stale `freeq-server` binary (Jun 19, predating the `freeq.at/msgsig` /
`freeq.at/act` caps) meant M4 initially had to be verified against
production. Chad repaired the Rust toolchain; `cargo build --release -p
freeq-server` now succeeds (1m47s) and the fresh binary advertises both caps.

**`npm run verify` now passes entirely locally, exit 0** — 117 unit tests plus
all four live harnesses (peers / ask / room / handoff). Production is no
longer needed for any part of the test suite; keep it for the recorded demo
only.

## Post-release fixes (found in real use on production)

### Agents flapped: connect / disconnect / re-register loop

Reported as "my agents keep disconnecting and reconnecting". Server logs
showed session ids in the **600s**, four concurrent sessions on one DID,
repeated `AGENT REGISTER`, ghost-mode churn, and a hello storm.

Two compounding bugs, both ours:

1. **Duplicate reconnect loops.** The SDK transport already auto-reconnects
   ("WebSocket IRC transport with auto-reconnect and heartbeat"), and bot-kit
   re-runs its announce sequence on every `ready`. `FreeqConnection` ALSO tore
   the bot down and built a fresh one on every `disconnected`, racing the
   transport's own retry and leaving several live sessions per DID. Removed:
   the transport owns reconnection; we only retry the *initial* connect.
2. **Dead state branches.** `TransportState` is only
   `disconnected | connecting | connected`, but the handler tested for
   `"ready"` and `"closed"` — branches that could never fire — while
   treating every `disconnected` as fatal. Also added a re-entrancy guard so
   two `start()` calls cannot build two bots.

Verified by `spike/churn-check.ts`, which forces the socket down mid-session:
**2 connections total** (initial + one transport reconnect), no
"other sessions remain for DID". Before the fix, a single blip multiplied.

### Every pi window fought over one identity

Opening a second pi window connected a second session as the SAME did:key and
nick. Legal server-side (multi-device siblings) but incoherent: presence is
last-writer-wins, so an idle window overwrote the working window's
`executing` status, and one mention was answered by every window.

`src/lock.ts` — a pid-file lock in the agent dir, so one session holds the
connection and the rest go passive (surfaced in `/freeq status`, moved with
`/freeq takeover`). A lock from a crashed session is reclaimed via a liveness
check rather than locking the machine out. 10 unit tests.

## Parked ideas (NOT scheduled — do not build)

### Summoning an AV agent into a call

*Raised by Chad, 2026-04. Captured only; no work planned.*

"Ask your pi to join a call" — i.e. a pi agent brings voice/video presence
into a freeq call.

The important architectural point: **pi would not join the call itself.** The
AV stack is Rust (`freeq_sdk::av` for signaling, `freeq-av` for the MoQ/SFU
media session, `freeq-agent-kit` for VAD/utterance helpers; Eliza is the
reference implementation). `@freeq/pi` is TypeScript. So the shape is
*summoning*: pi asks a separate AV-capable agent process to join on its
behalf, and talks to it over freeq like any other peer.

Why that's the right shape anyway, independent of the language split:
- keeps media out of the pi extension entirely (no realtime audio in the
  agent's event loop, no new failure mode for a coding session)
- the AV agent is a normal owned freeq bot, so identity, governance
  (pause/revoke) and provenance already apply to it
- it's a natural `handoff`/`act` consumer (M4): "summon" is a directed action
  to a known AV agent, or an open capability-matched offer
  (`act-caps=freeq.at/av`) that any AV-capable agent can claim

This is also already anticipated by the design doc: the HANDOFF RFC calls out
escalating an async action "into a live channel or voice room" as something a
pure HTTP inbox can't do. Summoning is that escalation, made concrete.

Open questions if it's ever picked up: who pays for / hosts the AV agent
process; whether the pi session gets the transcript back as inbound events
(tier-gated like everything else); and whether "summon" should be a distinct
verb or just a handoff with an AV capability.

## Open questions carried from the design doc (mine to resolve)

- **Tool shape** — starting with one `freeq({action})` tool; will report on
  model reliability after M2 and switch to `freeq_*` tools if it misfires.
- **Context export format** for handoffs — deferred to M4, markdown brief first.
- **Human-in-pi channel pane** — not building; freeq client in another pane.
- **Peer discovery mechanism** — resolved: application-level hello over
  coordination events (see finding above), not presence status.

## M3 scope addition (from the M0 leak)

The scrubber must redact **absolute filesystem paths** in outbound
`say`/`send`/reply text, in addition to secrets. Home directories and repo
roots identify the user and machine, and an agent answering "which repo are
you in?" will volunteer them unprompted.

## M0 evidence (acceptance met)

Acceptance criterion was: *"from irssi or irc.freeq.at web, ask the bot 'what
files are in your cwd?' and get a real answer."* Done, with a scripted driver
rather than a hand-typed client (`spike/send.ts`, which doubles as the CI
harness the spec asks for in §5):

```
[spike] up as pi-spike (did:key:z6MkhYwcH4ez9kBXWNbJ8MziHqrtoJic327zCi2MHYAjejUR)
        in #playground — owner did:plc:4qsyxmnsblo4luuycm3572bq
[send]  joined #playground; sending
[spike] <spike-driver> in one short sentence, what is the name of the git repo…
[spike] answered in 7.0s (109 chars)
[recv]  [#playground] <pi-spike> spike-driver: The repo is `freeq` (working dir
        `freeq-pi` is a subdirectory of the repo rooted at /Users/chad/src/freeq).
```

What this validates for the product: agent identity minting (`did:key`,
owner-bound, persisted 0600), SASL crypto auth, channel join, addressed-only
gating via `bot.checkMention`, untrusted-input framing, pi `AgentSession`
answering **from its own real filesystem**, and the answer-capture loop
(`session.subscribe` → `text_delta` accumulation) that M2's inbound `ask`
handler needs.

## Findings from M0 (feed into M1/M2)

1. **Answer capture works via `text_delta` accumulation** on
   `session.subscribe`, unsubscribing after `prompt()` resolves. M2 needs the
   same shape but must scope the buffer per inbound request (concurrent asks).
2. **Concurrency needs an explicit gate.** The spike uses a crude `busy` flag.
   Running two bot instances on one nick produced a `0 chars` answer — benign
   test artifact, but it shows an empty-answer path exists and M2 must treat
   "empty result" as an explicit failure reply, not silence.
3. **`resolveSenderDid()` returns `string | null`** — guests resolve to null,
   so the tier classifier must default null → lowest tier (OBSERVE).
4. **`checkMention` returns a discriminated union** (`respond` | `cooldown` |
   `ignore`) and gives per-channel cooldown for free — reuse in M2/M3 addressed
   mode instead of writing new throttling.
5. **Latency is ~5–7s** for a simple question. `ask` default timeout of 120s in
   the spec is comfortable; keep it.

## Next actions

- [x] Plan file
- [x] M0 spike: `freeq-pi/spike/spike-bot.ts` + live run against `#playground`
- [x] M0 driver/harness: `freeq-pi/spike/send.ts`
- [x] **M1**: `src/{config,identity,presence,connection,discovery}.ts`,
      `extensions/freeq.ts` with `/freeq login|status|join|leave|peers|mode|
      trust|on|off`; acceptance verified via `spike/peers-check.ts`
- [x] **M2**: `src/ask.ts`, `src/inbound.ts`, the `freeq` tool
      (`peers|ask|send|say`), skill + README, mandatory invariant test;
      mechanism verified by `spike/ask-check.ts`
- [ ] **M2 demo**: two people, two laptops, across the internet — **needs a
      second person**; record it (this is the deliverable to show the pi team)
- [x] **M3**: humans in the room (Demo 2), outbound scrubber, `/freeq mute`,
      batched notifications, DEMO.md — **v0.1 feature-complete**
- [x] **Two-MACHINE demo** — laptop ↔ reth, production server, full arc
      (refused → trust → answered → humans in the room). See `DEMO-RESULTS.md`.
      Everything mechanical in the v0.1 criterion is proven.
- [ ] **Re-run with a real second person** — the only remaining gap; both
      identities in tonight's run were Chad's. Then record it.
- [x] **M4**: handoffs — offer/accept/decline/progress/complete/cancel via the
      act substrate, human-gated accept, offline replay, `/freeq handoffs`,
      persisted view. 117 unit tests; acceptance verified on production.
- [x] **Re-verify M4 locally** — done; full `npm run verify` green against a
      freshly built local server
- [ ] Optional next: claimable/open handoffs (`act-caps`, no `act-to`) —
      substrate already supports them; only the tool surface is missing
- [ ] Optional next: verify inbound act signatures (needs per-DID key
      history; the RFC flags this as unbuilt)
