# @freeq/pi — implementation plan

Living document. Updated as work proceeds. Spec: `docs/PI-FREEQ-BUILD-SPEC.md`.
Design: `docs/PI-FREEQ-MULTIPLAYER.md`. Pitch: `docs/PI-FREEQ-PITCH.md`.

## Status

| milestone | state | notes |
|---|---|---|
| M0 — headless spike bot | **DONE** ✅ | proved live on `#playground` — see evidence below |
| M1 — package skeleton | **DONE** ✅ | two installs mutually visible w/ metadata + DIDs |
| M2 — tool + tiered inbound | **DONE** ✅ | cross-agent ask verified; tier gate holds |
| M3 — humans in the room | **next** | addressed mode, scrubber, docs |
| M4 — handoffs | not started | only after M3 demoed |

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
- [ ] **M3**: humans in the room (Demo 2), outbound scrubber (secrets **and
      absolute paths** — see the M0 leak), `/freeq mute`, batched OBSERVE
      notifications
