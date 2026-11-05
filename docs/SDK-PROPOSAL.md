# `@freeq/sdk-js` — Proposed Design

> Historical note: `freeqcc` became `freeq-cc`, a Claude Code plugin built on `freeq-harness-kit`, and the freeqcc daemon was removed. This proposal describes the daemon as it was.

A first-principles redesign of the TS SDK. Companion doc: [SDK-API-REFERENCE.md](./SDK-API-REFERENCE.md) — raw audit of current Rust + TS surfaces.

---

## Scope

The current TS SDK exposes **30 methods + 44 events**.

This proposal:
- **Adds 35 methods** — agent lifecycle (Phase 1), governance (Phase 2), coordination events (Phase 3), spawning (Phase 4), economics (Phase 5), plus a few messaging gaps (`quit`, `joinMany`, `sendTagged`, `sendMedia`, `startTyping`/`stopTyping`, etc.).
- **Adds 8 events** — `connected`, `disconnected`, `presence`, `governance`, `agentSpawned`, `agentDespawned`, `coordinationEvent`, `spend`, `budget`.
- **Renames 2 methods + 1 event** — `requestDmTargets` → `requestHistoryTargets`; `dmTarget` event → `historyTarget` (CHATHISTORY TARGETS includes channels, not just DMs); `whois` method → `requestWhois` (matches `request*` convention; event stays `whois`). Old names kept as deprecated aliases for one release.
- **Changes behavior of 2 methods** — `requestWhois(nick)` returns `Promise<WhoisInfo>` instead of fire-and-forget; `requestHistory` redesigned to take `opts: { mode: 'latest' | 'before' | 'after', msgid?, count? }` (currently has no `after` mode at all).
- **Unchanged** — every other existing method, event, E2EE surface, AV surface.

End state: **~70 methods + ~50 events**, covering everything Rust SDK's `ClientHandle` and `Event` enum cover today, plus the pre-parsed events TS already has and Rust lacks. Downstream of this proposal, `@freeq/bot-kit` gets built (a separate new package — currently doesn't exist) as ~300 LoC of file-on-disk persistence + announce-sequence orchestration on top of this SDK.

---

## Principles

1. **Two surfaces, no overlap.** Outbound = methods on the client (you call them). Inbound = events the client emits (you listen). No method waits-and-parses a follow-up wire response inline. No event is fired by your own call.
2. **TS idioms.** EventEmitter for inbound. `Promise` returns for outbound methods that need a server reply or completion. `async/await` everywhere.
3. **Consumers never see raw IRC.** The SDK pre-parses `+draft/edit`, `+react`, `+typing`, `+freeq.at/event=…`, MOTD, NAMES, CHATHISTORY batches, etc. and surfaces structured events. `client.raw()` exists only as an escape hatch.
4. **Naming is rule-based, not vibe-based.** Every method picks one prefix from a fixed table. No per-case judgment.
5. **One way to do a thing.** No method+event collisions. No method that does both A and B with an optional discriminator. No two methods that do the same thing differently (Rust has `react` and `send_reaction` today — pick one).
6. **Coverage parity with Rust SDK.** Every Rust `ClientHandle` method has a TS counterpart. Every Rust `Event` variant has a TS event. Naming follows TS conventions; mapping is documented.

---

## Shape

```ts
import { FreeqClient } from '@freeq/sdk';

const client = new FreeqClient({
  url: 'wss://irc.freeq.at/irc',
  nick: 'mybot',
  sasl: { method: 'crypto', did, signer },
  onNickCollision: 'refuse',  // | 'auto-suffix' | 'random-suffix'
});

// ── Inbound (events) — examples; full list below ──────────
client.on('ready', (nick) => { ... });
client.on('message', (channel, msg) => { ... });
client.on('memberJoined', (channel, member) => { ... });
client.on('coordinationEvent', (event) => { ... });
client.on('governance', (signal) => { ... });

// ── Outbound (methods) — examples; full list below ────────
await client.connect();                          // returns when 'ready' fires
await client.sendMessage('#chan', 'hello');
await client.registerAgent('agent');
await client.submitProvenance(cert);
const heartbeat = client.startHeartbeat(30_000); // returns handle with .stop()

// Methods that elicit a server reply return Promises
const info = await client.requestWhois('alice'); // resolves to WhoisInfo (includes DID)
const eventId = await client.emitEvent('#tasks', 'task_request', payload);

// Task sugar
const taskId = await client.createTask('#tasks', 'review PR #42');
await client.updateTask('#tasks', taskId, 'reviewing', 'fetching diff');
await client.completeTask('#tasks', taskId, 'approved with comments');
```

---

## Consumers

### Today

| Consumer | What it uses | Notes |
|---|---|---|
| **freeq-app** (web client) | ~40 of 44 events; typed methods: `sendMessage` / `sendEdit` / `sendDelete` / `sendReaction` / `sendReply` / `sendMarkdown` / `sendUnreact` / `join` / `part` / `kick` / `invite` / `setMode` / `setTopic` / `setAway` / `pin` / `unpin` / `whois` / `requestHistory` / `requestDmTargets` / `connect` / `disconnect` / `setSaslCredentials` / E2EE. Exactly **one** `client.raw()` call (a QUIT on disconnect). | Primary driver of the current SDK shape. Only one breaking change (`requestHistory` signature, ~5 LoC). See migration section below. |
| **freeqcc** | `generateDidKey` / `importDidKey`, `FreeqClient` with crypto SASL, `sendMessage`, `on('memberDid')` / `on('ready')` / `on('message')` / `on('raw')`. Heavy `client.raw()` for PROVENANCE, AGENT REGISTER, PRESENCE, HEARTBEAT, streaming PRIVMSG with custom tags, edits, NICK, QUIT. | 18 `client.raw()` calls for agent-native protocol (PROVENANCE, AGENT REGISTER, PRESENCE, HEARTBEAT, streaming-tagged PRIVMSGs, edit-tagged PRIVMSGs, NICK, JOIN, WHOIS, QUIT) because no typed methods exist. Migration swaps each for a typed call. |
| **freeq-swarm** (coordinator + worker) | Same crypto SASL, `on('memberDid')` / `on('memberJoined')` / `on('channelJoined')` / `on('userQuit')` / `on('userRenamed')` / `on('message')` / `on('raw')`. Heavy `client.raw()` for coordination event TAGMSG+PRIVMSG pairs, AGENT REGISTER, PRESENCE, HEARTBEAT. | External repo. Same `client.raw()` pattern for agent-native + coordination protocol. Wrote its own `freeq.ts` (296 LoC), `did_resolver.ts` (181 LoC), `governance.ts` (58 LoC) to fill SDK gaps. All three get deleted post-migration. |
| **examples/karma-bot** (350 LoC) | `connect` / `disconnect` / `nick` / `on` / `once` / `sendMessage`. | IRC karma tracker (`nick++`, `!karma`, `!leaderboard`); also drives the `/agent/tools/*` diagnostic surface. Unaffected. |
| **examples/logger-bot** (231 LoC) | `connect` / `disconnect` / `nick` / `on` / `once`. | Smallest useful example — writes every event to stdout + JSONL. Pure observer. Unaffected. |
| **examples/full-validation-bot** (276 LoC) | `connect` / `disconnect` / `nick` / `on` / `once` / `sendMessage`. | Flagship demo of did:key SASL + `/agent/tools/*` diagnostic surface — generates a fresh did:key, connects via crypto SASL, exercises every diagnostic tool. Unaffected. |

**Pattern:** the web client uses the full typed surface (it drove most of what exists today). freeqcc and swarm reach for `client.raw()` constantly because the agent-native + coordination verbs aren't in the TS SDK at all — they have no choice. The current SDK covers human-facing chat well; it doesn't cover agent-facing protocol.

### Future (after this proposal lands)

| Consumer | Status | Why this proposal matters to them |
|---|---|---|
| **@freeq/bot-kit** | new package (doesn't exist yet) | Will compose `submitProvenance` + `registerAgent` + `setPresence` + `startHeartbeat` + `join` into the announce sequence. Each bot today reinvents this; bot-kit centralizes it on top of the SDK additions in this proposal. |
| **freeq-bots (TS port)** | replacement for current Rust freeq-bots | First clean consumer of the agent-native + coordination-event surface. Built on top of bot-kit. |
| **freeqcc** | already works via `raw()`; no mandatory changes | Recommended cleanup: ~18 `client.raw()` calls → typed methods (`submitProvenance`, `setPresence`, `sendHeartbeat`, `sendTagged`, `sendEdit`, etc.). ~50 LoC of hand-rolled DID-cache plumbing deletable. No method signature changes affect it. |
| **freeq-swarm** | already works via `raw()`; no mandatory changes | Recommended cleanup: deletes ~700 LoC of shim modules (`freeq.ts`, `did_resolver.ts`, `governance.ts`) it wrote to fill SDK gaps. No method signature changes affect it. |

The current SDK serves the web client well and everyone else poorly. The proposed surface closes that gap.

---

## Naming rules

Every method picks **one** prefix from this table. No exceptions.

| Prefix | When | Example |
|---|---|---|
| bare verb | basic IRC verbs and channel ops | `join`, `part`, `quit`, `kick`, `invite`, `pin`, `unpin`, `raw` |
| `set*` | replace/update a state field | `setMode`, `setTopic`, `setAway`, `setPresence`, `setBudget`, `setSaslCredentials` |
| `send*` | emit one outbound message | `sendMessage`, `sendReply`, `sendReaction`, `sendEdit`, `sendDelete`, `sendUnreact`, `sendMedia`, `sendLinkPreview`, `sendHeartbeat`, `sendMarkdown`, `sendTagged`, `sendTagmsg`, `sendAndAwaitEcho`, `sendReplyInThread`, `sendAsChild` |
| `request*` | command eliciting a server reply stream | `requestApproval`, `requestHistory`, `requestHistoryTargets`, `requestWhois`, `requestBudget` |
| `submit*` | one-shot structured declaration | `submitProvenance`, `submitManifest` |
| `emit*` | TAGMSG+PRIVMSG coordination event pair | `emitEvent` |
| `start*` / `stop*` | begin/end background loop or transient state | `startHeartbeat`, `startTyping`, `stopTyping` |
| `fetch*` | async REST retrieval | `fetchPins` |
| `get*` | getter for a single value (sync or async via Promise) | `getSafetyNumber`, `getDidForNick`, `getNickForDid` |
| `remove*` | undo a `set*` | `removeChannelEncryption` |
| `initialize*` | one-time setup | `initializeE2EE` |
| `*Agent` suffix | AGENT verb subcommands | `registerAgent`, `pauseAgent`, `resumeAgent`, `revokeAgent`, `approveAgent`, `denyAgent`, `spawnAgent`, `despawnAgent` |
| lifecycle verbs | task entities (sugar over `emitEvent`) | `createTask`, `updateTask`, `completeTask`, `failTask`, `attachEvidence` |

---

## Outbound — full method surface

### Connection & reconnect

```ts
new FreeqClient(opts: FreeqClientOptions)
client.connect(): Promise<void>           // resolves on 'ready'
client.disconnect(): void
client.reconnect(): void
client.quit(reason?: string): Promise<void>
client.raw(line: string): void
client.setSaslCredentials(creds): void
// runWithReconnect — deferred to @freeq/bot-kit (the reconnect-with-rejoin loop is bot-shaped; the SDK exposes the primitives the loop needs).
```

### Channels

```ts
client.join(channel): Promise<void>
client.joinMany(channels[]): Promise<void>
client.part(channel, reason?): Promise<void>
client.kick(channel, nick, reason?): Promise<void>
client.invite(channel, nick): Promise<void>
client.setMode(channel, flags, arg?): Promise<void>
client.setTopic(channel, text): Promise<void>
client.pin(channel, msgid): Promise<void>
client.unpin(channel, msgid): Promise<void>
client.requestWhois(nick): Promise<WhoisInfo>    // renamed from `whois`; old name kept as deprecated alias one release
```

### Messaging

```ts
client.sendMessage(target, text, opts?: {multiline?}): Promise<void>
client.sendMarkdown(target, text): Promise<void>
client.sendReply(target, replyToMsgId, text, opts?: {multiline?}): Promise<void>
client.sendReplyInThread(target, parentMsgId, text): Promise<void>
client.sendReaction(target, emoji, msgId): Promise<void>
client.sendUnreact(target, emoji, msgId): Promise<void>
client.sendEdit(target, originalMsgId, newText, opts?: {multiline?}): Promise<void>
client.sendDelete(target, msgId): Promise<void>
client.sendMedia(target, media: MediaAttachment): Promise<void>
client.sendLinkPreview(target, preview: LinkPreview): Promise<void>
client.sendTagged(target, text, tags): Promise<void>
client.sendTagmsg(target, tags): Promise<void>
client.sendAndAwaitEcho(target, text, tags): Promise<string>  // returns msgid
```

### Typing & away

```ts
client.startTyping(target): Promise<void>
client.stopTyping(target): Promise<void>
client.setAway(reason?): Promise<void>
```

### History

```ts
client.requestHistory(channel, opts: {
  mode: 'latest' | 'before' | 'after',
  msgid?: string,
  count?: number,
}): Promise<void>
client.requestHistoryTargets(limit?): Promise<void>
client.fetchPins(channel): Promise<PinnedMessage[]>
```

### Identity resolution

```ts
client.getDidForNick(nick): string | undefined   // sync, cached
client.getNickForDid(did): string | undefined    // sync, cached
client.requestWhois(nick): Promise<WhoisInfo>    // async, fires WHOIS, awaits 330
```

> **Agent-oriented surface (next five subsections).** The "Phase N" labels reference the freeq [agent-native roadmap](../freeq-site/docs/agent-native/) — incremental capabilities the server has rolled out (identity → governance → coordination → spawning → economics). All five are server-supported today; the proposal adds typed methods so TS bots stop reaching for `client.raw()`.

### Agent lifecycle (Phase 1)

```ts
client.registerAgent(class): Promise<void>
client.submitProvenance(json): Promise<void>
client.setPresence(state, status?, task?): Promise<void>
client.sendHeartbeat(state, ttl): Promise<void>
client.startHeartbeat(interval): HeartbeatHandle   // returns { stop() }
```

### Governance (Phase 2)

```ts
client.requestApproval(channel, capability, resource?): Promise<void>
client.pauseAgent(nick, reason?): Promise<void>
client.resumeAgent(nick): Promise<void>
client.revokeAgent(nick, reason?): Promise<void>
client.approveAgent(nick, capability): Promise<void>
client.denyAgent(nick, capability, reason?): Promise<void>
```

### Coordination events (Phase 3)

```ts
client.emitEvent(channel, eventType, payload, opts?: {
  refId?: string,
  humanText?: string,
}): Promise<string>   // returns eventId

// Sugar over emitEvent
client.createTask(channel, description): Promise<string>           // returns taskId
client.updateTask(channel, taskId, phase, summary): Promise<void>
client.completeTask(channel, taskId, summary, url?): Promise<void>
client.failTask(channel, taskId, error): Promise<void>
client.attachEvidence(channel, taskId, evidenceType, summary, url?): Promise<void>
```

### Spawning (Phase 4)

```ts
client.submitManifest(toml): Promise<void>
client.spawnAgent(channel, nick, capabilities[], ttl?, taskRef?): Promise<void>
client.despawnAgent(nick): Promise<void>
client.sendAsChild(childNick, channel, text): Promise<void>
```

### Economics (Phase 5)

```ts
client.submitSpend(channel, amount, unit, description, taskRef?): Promise<void>
client.setBudget(channel, max, unit, period, sponsorDid): Promise<void>
client.requestBudget(channel): Promise<void>
```

### E2EE (existing, unchanged)

```ts
client.initializeE2EE(did): Promise<void>
client.setChannelEncryption(channel, passphrase): Promise<void>
client.removeChannelEncryption(channel): void
client.getSafetyNumber(remoteDid): Promise<string | null>
```

---

## Inbound — full event surface

All events fire on the typed EventEmitter (`client.on(event, handler)`). Payload shapes shown.

### Connection lifecycle

```ts
client.on('connectionStateChanged', (state: TransportState) => ...)
client.on('connected',              () => ...)            // TCP/WS established
client.on('registered',             (nick: string) => ...) // IRC registration done
client.on('authenticated',          (did, message) => ...)
client.on('authError',              (error: string) => ...)
client.on('ready',                  (nick: string) => ...) // registered + initial channels joined
client.on('disconnected',           (reason: string) => ...)
client.on('error',                  (message: string) => ...)
```

### Channel membership

```ts
client.on('channelJoined',    (channel) => ...)               // we joined
client.on('channelLeft',      (channel) => ...)               // we left
client.on('memberJoined',     (channel, member) => ...)       // someone else joined
client.on('memberLeft',       (channel, nick, reason?) => ...) // someone else left
client.on('userKicked',       (channel, kicked, by, reason) => ...)
client.on('userQuit',         (nick, reason) => ...)
client.on('userRenamed',      (oldNick, newNick) => ...)
client.on('nickChanged',      (nick) => ...)                  // our own nick changed
client.on('userAway',         (nick, reason) => ...)
client.on('invited',          (channel, by) => ...)
client.on('membersList',      (channel, members[]) => ...)    // NAMES complete
```

### Messages

```ts
client.on('message',          (channel, msg: Message) => ...)
client.on('messageEdited',    (channel, originalMsgId, newText, newMsgId?, isStreaming?) => ...)
client.on('messageDeleted',   (channel, msgId) => ...)
client.on('reactionAdded',    (channel, msgId, emoji, fromNick) => ...)
client.on('reactionRemoved',  (channel, msgId, emoji, fromNick) => ...)
client.on('systemMessage',    (target, text) => ...)          // server NOTICE
client.on('motd',             (line) => ...)
client.on('motdStart',        () => ...)
```

### Channel state

```ts
client.on('topicChanged',     (channel, topic, setBy?) => ...)
client.on('modeChanged',      (channel, mode, arg?, setBy) => ...)
client.on('pinAdded',         (channel, msgid, pinnedBy) => ...)
client.on('pinRemoved',       (channel, msgid) => ...)
client.on('pins',             (channel, pins[]) => ...)        // PIN list (REST or IRC reply)
client.on('channelListEntry', (entry) => ...)                  // LIST entries
client.on('channelListEnd',   () => ...)
client.on('joinGateRequired', (channel) => ...)
```

### Indicators

```ts
client.on('typing', (channel, nick, isTyping) => ...)
```

### Identity

```ts
client.on('memberDid', (nick, did) => ...)
client.on('whois',     (nick, info: WhoisInfo) => ...)
```

### History

```ts
client.on('historyBatch', (channel, messages[]) => ...)
client.on('dmTarget',     (nick, timestamp?) => ...)           // ⚠ rename → 'historyTarget' (alias for one release)
```

### Agent presence & governance

```ts
client.on('presence',  (nick, did, {state, status?, task?}) => ...)
client.on('governance', (signal: GovernanceSignal, target, by?, reason?) => ...)
client.on('agentSpawned',   (parentNick, childNick, channel, capabilities, ttl?) => ...)
client.on('agentDespawned', (nick, reason?) => ...)
```

### Coordination

```ts
client.on('coordinationEvent', (event: {
  channel, from, did?,
  eventType: string,
  eventId: string,
  taskId?: string,
  evidenceType?: string,
  payload: unknown,
}) => ...)
```

### Economics

```ts
client.on('spend',  (channel, did, amount, unit, description, taskRef?) => ...)
client.on('budget', (channel, {policy, currentPeriod}) => ...)
```

### AV signaling (existing, unchanged)

```ts
client.on('avSessionUpdate',  (session) => ...)
client.on('avSessionRemoved', (sessionId) => ...)
client.on('avTicket',         (sessionId, ticket) => ...)
```

### Raw

```ts
client.on('raw', (line, parsed) => ...)   // escape hatch
```

---

## Comparison

### vs. current `@freeq/sdk-js`

**Added (26 outbound methods):**
`quit`, `joinMany`, `sendAndAwaitEcho`, `sendTagged`, `sendTagmsg`, `sendMedia`, `sendLinkPreview`, `sendReplyInThread`, `startTyping`, `stopTyping`, `registerAgent`, `submitProvenance`, `setPresence`, `sendHeartbeat`, `startHeartbeat`, `requestApproval`, `pauseAgent`, `resumeAgent`, `revokeAgent`, `approveAgent`, `denyAgent`, `emitEvent`, `createTask`, `updateTask`, `completeTask`, `failTask`, `attachEvidence`, `submitManifest`, `spawnAgent`, `despawnAgent`, `sendAsChild`, `submitSpend`, `setBudget`, `requestBudget`, `getDidForNick`, `getNickForDid`. (`runWithReconnect` deferred to bot-kit.)

**Behavior changes (2):**
- `whois(nick)` renamed to `requestWhois(nick)` and returns `Promise<WhoisInfo>` (today: fire-and-forget; you have to also listen for the `whois` event). Old `whois(nick)` kept as deprecated alias for one release.
- `requestHistory` redesigned to take an `opts: {mode, msgid?, count?}` object. Today's `(channel, before?)` had no `after` mode at all.

**Renamed (1):**
- `requestDmTargets` → `requestHistoryTargets` (misnomer; CHATHISTORY TARGETS includes channels). Old name kept as deprecated alias one release.
- `dmTarget` event → `historyTarget` (same reasoning).

**Added (8 inbound events):**
`connected`, `disconnected`, `presence`, `governance`, `agentSpawned`, `agentDespawned`, `coordinationEvent`, `spend`, `budget`.

**Unchanged:** all existing event names, all existing E2EE and AV methods, all existing send/set/request patterns.

### vs. `freeq-sdk` (Rust)

**Coverage parity:** every Rust `ClientHandle` method has a TS counterpart. Every Rust `Event` variant has a TS event (most have a richer pre-parsed TS event — see below).

**Where TS diverges by design:**

| Concern | Rust | TS | Why |
|---|---|---|---|
| Pre-parsing | Exposes raw `TagMsg`, consumers parse | Exposes `messageEdited`, `messageDeleted`, `reactionAdded`, `reactionRemoved`, `typing`, `pinAdded`, `pinRemoved`, `memberDid` directly | Consumers shouldn't re-parse tags. SDK does it once. |
| Self vs other | Single `Joined` / `Parted` / `NickChanged` | Splits into `channelJoined` (self) + `memberJoined` (other), similar for left/renamed | TS users don't have to `if (nick === me) {…}` |
| Connection lifecycle | Discrete `Connected` / `Disconnected` | `connectionStateChanged(state)` + discrete `connected` / `disconnected` / `ready` | TS UIs want both — the state machine and the discrete transitions |
| History batches | Raw `BatchStart` + messages + `BatchEnd` | Aggregated `historyBatch(channel, messages[])` | TS consumers want the collected result; raw markers stay via `raw` event |
| Names list | Raw `Names` + `NamesEnd` | Aggregated `membersList(channel, members[])` | Same — consumers want the final list |
| `whois` | Method fires; consumer awaits `WhoisReply` event | Method renamed to `requestWhois`, returns `Promise<WhoisInfo>` | TS async/await idiom; rename matches `request*` family |
| Naming | `AuthFailed`, `Joined`, `Parted`, `Kicked`, `AwayChanged`, `NickChanged`, `ServerNotice`, `ChatHistoryTarget` | `authError`, `memberJoined` / `channelJoined`, `memberLeft` / `channelLeft`, `userKicked`, `userAway`, `userRenamed` / `nickChanged`, `systemMessage`, `historyTarget` | TS noun-subject form; Rust verb form. Documented in [audit](./SDK-API-REFERENCE.md). |

**Where Rust should add to match TS** (downstream Rust work, out of this proposal's scope):
- Convenience methods: `part`, `kick`, `invite`, `set_away`, `send_markdown`, `send_unreact` (today require `raw`).
- Parsed event variants: `MessageEdited`, `MessageDeleted`, `ReactionAdded`, `ReactionRemoved`, `Typing`, `MemberDid`, `PinAdded`, `PinRemoved`, `Presence`, `Governance`, `CoordinationEvent`, `Spend`, `Budget`, `Error`.

**Redundancies to clean up in Rust:** `react` and `send_reaction` do the same thing — pick one.

---

## Open decisions

These need answers before implementation begins:

1. ~~**Self-vs-other split in inbound events.**~~ **Decided: keep split.** Status quo (`channelJoined` + `memberJoined`, etc.) stays. Consumers avoid `if (nick === me)` boilerplate; freeq-app keeps working unchanged. See "Future considerations" below for the unify-with-`isSelf` alternative if we ever reconsider.

2. ~~**History batches.**~~ **Decided: aggregate-only.** Status quo (`historyBatch(channel, messages[])`) stays. No consumer currently needs the BATCH start/end markers. See "Future considerations" for the marker-event alternative.

3. ~~**`whois` method renamed to avoid method/event collision.**~~ **Decided: rename to `requestWhois`.** Method becomes `requestWhois(nick): Promise<WhoisInfo>`. Event stays `'whois'`. Old `whois(nick)` method kept as deprecated alias for one release. Aligns with `request*` family (all elicit server replies).

4. ~~**`sendReaction` signature.**~~ **Decided: keep flat.** Status quo `sendReaction(target, emoji, msgId?)` stays. No breaking change to freeq-app. See "Future considerations" for the struct-aligned alternative if reactions ever grow fields.

5. ~~**`fetchPins` return type.**~~ **Decided: return `Promise<PinnedMessage[]>`.** Aligns with the `fetch*` naming rule ("REST retrieval, async — returns data"). `pins` event still fires for any subscribers. Non-breaking: no caller uses the current void return today.

---

## Future considerations

Deferred design alternatives — not part of this proposal, but worth recording so they're not forgotten:

- **Self-vs-other event unification** (deferred from Decision 1). Could collapse `channelJoined` + `memberJoined` into a single `joined(channel, member, isSelf)` event, matching Rust's `Event::Joined`. Trade-off: more wire-faithful, but every consumer writes the `isSelf` branch every time. Revisit if the duplication ever becomes a real cost.

- **Expose history batch markers** (deferred from Decision 2). Could add `historyBatchStart(channel, batchId)` and `historyBatchEnd(channel, batchId)` events alongside the aggregated `historyBatch`. SDK already parses the markers internally; adding the emits is ~5 LoC. Use cases: spinner state ("server is actively sending"), distinguishing pushed replay batches from live activity. Revisit when a consumer actually needs progressive loading UX.

- **`sendReaction` struct signature** (deferred from Decision 4). Could align with Rust's `send_reaction(target, Reaction)` by accepting a `Reaction` object. Future-proofs for richer reactions (custom emoji, sender attribution, etc.) but is a breaking change today and no concrete need exists. Revisit if reactions grow new fields.

---

## Migration steps per existing consumer

**Important framing:** This proposal is **additive**. `client.raw()` remains the escape hatch, so every existing consumer continues to function unchanged when the new methods/events land. The only hard breaking change in this proposal is the `requestHistory` signature (freeq-app only).

Everything else — replacing `client.raw('PROVENANCE ...')` with `submitProvenance(json)`, etc. — is **opt-in cleanup** done at each consumer's own pace.

### freeq-app (web client)

**Mandatory (breaking):**
- `requestHistory(channel, before?)` → `requestHistory(channel, opts: { mode, msgid?, count? })`. 3 sites:
  - [freeq-app/src/irc/client.ts:198](freeq-app/src/irc/client.ts#L198) — wrapper signature
  - [freeq-app/src/components/MessageList.tsx:1141](freeq-app/src/components/MessageList.tsx#L1141) — `requestHistory(activeChannel)`
  - [freeq-app/src/components/MessageList.tsx:1155](freeq-app/src/components/MessageList.tsx#L1155) — `requestHistory(activeChannel, oldest.timestamp.toISOString())`
- ~5 LoC swap.

**Deprecation-window (alias keeps current code working for one release):**
- `requestDmTargets(limit)` → `requestHistoryTargets(limit)` — 1 wrapper site
- `client.on('dmTarget', ...)` → `client.on('historyTarget', ...)` — 1 listener site
- `client.whois(nick)` → `client.requestWhois(nick)` — 1 wrapper site at [freeq-app/src/irc/client.ts:195](freeq-app/src/irc/client.ts#L195)
- Migrate when convenient. ~4 LoC eventual.

**Optional (new capability):**
- Swap the one `client.raw('QUIT :Leaving')` for `client.quit('Leaving')` — 1 line.
- Adopt new inbound events (`coordinationEvent`, `governance`, `presence`, `agentSpawned`, `agentDespawned`, `spend`, `budget`) if/when you want to render agent activity in the UI.

### freeqcc

**Mandatory:** none. freeqcc keeps working unchanged when this SDK lands — `client.raw()` stays the escape hatch.

**Recommended cleanup (no urgency, no deadline)** — swap `client.raw()` calls for typed methods to reduce surface area and benefit from type-checking:
- `connect.ts:91` `client.raw('PROVENANCE :...')` → `submitProvenance(cert)`
- `connect.ts:96` `client.raw('AGENT REGISTER :class=agent')` → `registerAgent('agent')`
- `connect.ts:99`/`148` `client.raw('PRESENCE :...')` → `setPresence(state)`
- `connect.ts:105` `client.raw('HEARTBEAT :...')` + manual interval → `startHeartbeat(30_000)` background loop helper
- `connect.ts:149` `client.raw('QUIT :...')` → `quit(reason)`
- `connect.ts:83` `client.raw('NICK ...')` → add a `setNick()` method (currently neither SDK has one — small parity gap)
- `daemon.ts:95` `client.raw('JOIN ...')` → `join(channel)`
- `daemon.ts:172`/`189` `client.raw('WHOIS ...')` + listener pattern → `await client.requestWhois(nick)` Promise
- `daemon.ts:240`/`407` PRESENCE state changes → `setPresence(state, status?)`
- `daemon.ts:282` streaming-tagged PRIVMSG → `sendTagged(target, text, { '+freeq.at/streaming': '1' })`
- `daemon.ts:295`/`382` `@+draft/edit=msgid PRIVMSG` → `sendEdit(target, msgid, text)`
- `daemon.ts:349`/`364` plain PRIVMSG → `sendMessage(target, text)`
- Replace hand-rolled `nickToDid` Map + `pendingByNick` queue ([daemon.ts:156-203](https://github.com/freeq-irc/freeq/blob/427478a56dd0e364073db8a8e6c59126437990c5/freeqcc/src/daemon.ts#L156-L203)) with SDK's `getDidForNick` / `requestWhois`.

Net: ~18 raw() calls → typed methods, plus ~50 LoC of DID-cache plumbing deleted.

### freeq-swarm

**Mandatory:** none. swarm keeps working unchanged when this SDK lands.

**Recommended cleanup** — bigger win here than freeqcc because swarm has written entire local shim modules to fill the SDK gap:
- Delete [`packages/shared/src/freeq.ts`](https://github.com/chad/freeq-swarm/blob/main/packages/shared/src/freeq.ts) (296 LoC) — `emitEvent` / `subscribeCoordinationEvents` / parse / build all become SDK calls.
- Delete [`packages/shared/src/did_resolver.ts`](https://github.com/chad/freeq-swarm/blob/main/packages/shared/src/did_resolver.ts) (181 LoC) — `getDidForNick` / `getNickForDid` / `requestWhois` move to SDK.
- Delete [`packages/shared/src/governance.ts`](https://github.com/chad/freeq-swarm/blob/main/packages/shared/src/governance.ts) (58 LoC parse logic) — `client.on('governance', ...)` covers it.
- Refactor [`packages/shared/src/connect.ts`](https://github.com/chad/freeq-swarm/blob/main/packages/shared/src/connect.ts) (175 LoC) — collision policy moves to `ConnectConfig.onNickCollision`; rest collapses or moves to bot-kit.
- Refactor [`packages/shared/src/announce.ts`](https://github.com/chad/freeq-swarm/blob/main/packages/shared/src/announce.ts) (94 LoC) — moves to bot-kit (still exists as orchestration; just lives elsewhere).
- All `client.raw('TAGMSG ...')` / `client.raw('PRIVMSG ...')` coordination calls in coordinator + worker → `emitEvent(...)`.

Net: shared/ shrinks by ~700 LoC; coordinator + worker swap raw-string assembly for typed method calls.

### Example bots (karma-bot, logger-bot, full-validation-bot)

**Mandatory:** none. They use simple typed methods (`connect`, `disconnect`, `sendMessage`, `on`) that aren't touched by this proposal.

**Optional:** can be updated post-landing to demonstrate the new agent-native surface, or stay as basic-bot examples.

---

## Summary

| | Count |
|---|---|
| Methods total (proposed) | ~70 |
| Methods in current TS | 30 |
| Methods to add | 35 |
| Methods to rename | 1 |
| Methods to change behavior | 2 |
| Events total (proposed) | ~50 |
| Events in current TS | 44 |
| Events to add | 8 |
| Events to rename | 1 |

bot-kit work is downstream from this. Once the SDK proposal is locked, bot-kit becomes ~300 LoC of file-on-disk persistence + announce-sequence orchestration on top.
