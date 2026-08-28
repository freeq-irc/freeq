# @freeq/pi — implementation plan

Living document. Updated as work proceeds. Spec: `docs/PI-FREEQ-BUILD-SPEC.md`.
Design: `docs/PI-FREEQ-MULTIPLAYER.md`. Pitch: `docs/PI-FREEQ-PITCH.md`.

## Status

| milestone | state | notes |
|---|---|---|
| M0 — headless spike bot | **DONE** ✅ | proved live on `#playground` — see evidence below |
| M1 — package skeleton | **next** | identity, connection, presence, commands |
| M2 — tool + tiered inbound | not started | **the core**; v0.1 acceptance |
| M3 — humans in the room | not started | addressed mode, scrubber, docs |
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
- [ ] **M1**: `src/identity.ts`, `src/connection.ts`, `src/presence.ts`,
      `src/config.ts`, `extensions/freeq.ts` with `/freeq login|status|join|
      leave|peers`; acceptance = two installs see each other in `/freeq peers`
