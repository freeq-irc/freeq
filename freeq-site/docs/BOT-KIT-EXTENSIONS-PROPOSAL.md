# `@freeq/bot-kit` extensions — Proposal

> Historical note: `freeqcc` became `freeq-cc`, a Claude Code plugin built on `freeq-harness-kit`, and the freeqcc daemon was removed. This proposal describes the daemon as it was.

Application-level primitives that two real consumers (freeqcc, freeq-swarm)
have independently reinvented. After the lifecycle migration landed
(`feat(freeqcc): migrate to @freeq/bot-kit for identity + lifecycle`),
bot-kit owns identity + delegation + announce + heartbeat + presence +
stop. This proposal adds the layer immediately above that: *who do I
respond to, when, and how is the bot operated*.

---

## Context

bot-kit today gets a bot from "I have a did:key on disk" to "I'm
announced, heartbeating, and receiving SDK events." Useful but a bot
author still hits five problems before they ship anything:

1. **Who is this person?** A PRIVMSG arrives with a nick. The bot needs
   the sender's DID — for the gate, the audit log, the response.
   freeqcc + swarm both wrote: try account-tag → look up cached
   nick→DID → fire WHOIS → wait with timeout → cache → enforce.
2. **Should I answer them?** Bots that aren't open-mic need a list of
   trusted DIDs. freeqcc has `~/.freeqcc/allowlist.json` with
   live-reload + per-entry metadata. swarm has `operator_allowlist`
   in its YAML config (no live-reload — restart to change).
3. **Was I @-mentioned in this channel?** freeqcc has `isMention()`
   regex + 60s per-channel cooldown. swarm has `ADDRESSING_RE` regex
   + `stripAddressing()`. Same problem, two regexes.
4. **Am I being rate-limited or looping?** freeqcc has `gate.ts`
   (~180 LOC): dispatch-to-dispatch cooldown, rolling hourly cap,
   bot↔bot cycle detection, persisted state. swarm has *dollar*-based
   limits (BUDGET endpoint) — different axis, doesn't generalize.
5. **How does my user run me?** freeqcc has `launch | stop | status |
   doctor | tail | rotate-key | grant | revoke`. swarm has `swarm
   coordinator` / `swarm worker` — no status, no doctor, no graceful
   stop. Bot authors copy-paste freeqcc's CLI shape if they want
   anything more than `nohup`.

End state: bot-kit ships five new primitives — `resolveSenderDid`,
`createAllowlist`, `createMentionFilter`, `createTurnGate`,
`createDaemonCLI`. A bot author writes domain logic; everything else is
imported.

---

## Principles

1. **Small, composable primitives.** Each export does one thing, has
   one config object, returns one helper. No god-object.
2. **No new wire protocol or server-side work.** Pure consumer-side
   helpers built on what `@freeq/sdk` already exposes.
3. **Pluggable, opinionated defaults.** Every primitive has sensible
   defaults so a new bot can adopt it in one line; every primitive
   accepts an options bag for non-default cases.
4. **No coupling between primitives.** A bot can adopt `createMentionFilter`
   without adopting `createTurnGate`. A bot can use `createAllowlist`
   without `resolveSenderDid` (e.g. swarm reads DIDs from a YAML at
   startup).
5. **Don't generalize freeqcc's claude-specific defaults.** The
   dispatch-cost cap, the per-action capability matrix, the
   control-socket subprocess pattern — those stay in freeqcc.

---

## Survey: current shape in each consumer

| Concern              | freeqcc                                | freeq-swarm                          |
| -------------------- | -------------------------------------- | ------------------------------------ |
| Identity (did:key)   | ✅ now via bot-kit                     | ❌ own `shared/identity.ts` (44 LOC) |
| Delegation cert      | ✅ now via bot-kit                     | ❌ own `shared/delegation.ts` (89)   |
| Connect + announce   | ✅ now via bot-kit                     | ❌ own `shared/connect.ts` (175) + `announce.ts` (94) |
| Sender DID resolver  | `daemon.ts:161-203` (~50 LOC)          | `dispatcher.ts:64-68` (3 LOC, no WHOIS fallback) |
| Trusted-DID list     | `allowlist.ts` (131 LOC) — JSON, live-reload, per-entry metadata | `policy.ts:26` — YAML, startup only, string array |
| Mention parsing      | `daemon.ts:417-426` — regex + 60s cooldown | `ingest.ts:42-72` — regex, no cooldown |
| Rate limiting        | `gate.ts` (181 LOC) — turn-based       | `budget.ts` — dollar-based, server-side |
| Daemon CLI surface   | `cli.ts` (636 LOC) — full              | `cli/src/index.ts` (21 LOC) — dispatcher only |

freeqcc has the richer implementation of every shared concern. swarm
either reinvented less or skipped the cap entirely.

---

## Proposed additions

### 1. `bot.resolveSenderDid(msg, opts?)`

Method on `FreeqBot`. Resolves the DID of a PRIVMSG/CHANNEL sender,
using the cheapest source available, with WHOIS fallback and timeout.

```ts
const did = await bot.resolveSenderDid(msg, { timeoutMs: 3000 });
if (!did) {
  // Could not resolve — guest, network failure, or timeout.
}
```

Internally:

1. **Synchronous path** — if `msg.tags.account` exists and starts with
   `did:`, return it immediately. (No round-trip. Authoritative for
   the message — see "Cache safety" below.)
2. **Cache path** — `FreeqBot` maintains a `nick → did` cache, populated
   automatically by the SDK's `memberDid` event. If the cache has the
   sender, return it.
3. **WHOIS path** — fire `WHOIS <nick>`, register a one-shot listener
   on `memberDid` for that nick, race against `setTimeout(timeoutMs)`.
   On resolve, cache and return; on timeout, return `null`.

Bot-kit owns the cache + dedup of concurrent WHOIS-for-same-nick.

**Cache safety.** A naive nick→DID cache is unsafe: Alice quits, Bob
acquires the nick `alice`, the bot now has a stale entry mapping
`alice` to Alice's DID and could allowlist Bob as Alice if Bob's
PRIVMSG arrives without `account-tag`. freeqcc's current cache
(`daemon.ts:159-167`) is missing this invalidation — it's a latent
bug we're fixing here, not just generalizing. The contract for this
primitive:

1. **`msg.tags.account` is always preferred over the cache.** The
   account tag is attached by the server at message-arrival time and
   cannot be stale; the cache can. With `account-tag` cap negotiated
   (default on freeq), every SASL-authed user's PRIVMSG carries it,
   so the cache is consulted rarely in practice.
2. **Aggressive invalidation.** Bot-kit listens to the SDK and:
   - `userRenamed(from, newNick)` → drop `from`. (Optional: rebind to
     `newNick` if we know the DID is invariant across a NICK command,
     which it is for the freeq server.)
   - `userQuit(from)` → drop `from`.
   - `memberDid(nick, did)` → overwrite (server's latest view wins).
3. **Strict mode for security-sensitive bots.** Opt in with
   `{ requireAccountTag: true }`. The cache and WHOIS are bypassed
   entirely; senders without account-tag get `null`. Bots that
   refuse on `null` get a hard no-stale-DID guarantee.

Trade-off: the cache turns "second message from a known nick"
from a 1-3s WHOIS round-trip into an instant lookup, at the cost of
a sub-second invalidation window between `userQuit` firing and the
nick being re-acquired. With aggressive invalidation that window is
short; with `requireAccountTag` it doesn't exist.

**Replaces:**
- freeqcc/daemon.ts:156-203 (~50 LOC including the `nickToDid` map,
  `pendingByNick` queue, and the WHOIS race in `handleDm`).
- swarm/dispatcher.ts:64-68 — though swarm currently has no WHOIS
  fallback so adopting this is a small upgrade as well.

### 2. `createAllowlist({ load, watch?, schema? })`

Standalone factory (not a `FreeqBot` method — bots may use it before
they construct the bot). Returns an object exposing `.has(did)`,
`.list()`, `.metadata(did) → T | null`, plus a `change` event when the
backing file is updated.

```ts
const allowlist = await createAllowlist<MyMeta>({
  load: () => loadFromJsonFile("~/.mybot/allowlist.json"),
  watch: "~/.mybot/allowlist.json",  // optional — enables live-reload
});

if (!allowlist.has(senderDid)) refuse();
```

- `load: () => Promise<Entry[] | string[]>` — caller-owned loader.
  Accepts either a string array (just DIDs) or `Entry[]` where
  `Entry = { did: string, ...meta }`. String entries are normalized to
  `{ did }`.
- `watch?: string` — if provided, bot-kit polls the file's mtime every
  2s (same approach freeqcc uses today) and re-runs `load()` on change.
- `schema?: ZodSchema | (e: unknown) => Entry` — optional validator;
  invalid entries are dropped with a warning rather than crashing the
  daemon.

Bot-kit ships a `loadFromJsonFile(path)` convenience that does
`JSON.parse` + array check. Bots that want YAML or env-var sources just
pass their own `load`.

**Replaces:**
- freeqcc/allowlist.ts (131 LOC, including the live-reload polling
  duplicated in daemon.ts:130-150).
- swarm/dispatcher.ts:71 — swarm gets free live-reload as a
  side-effect.

### 3. `createMentionFilter({ botNick, cooldownMs?, addressingStyle? })`

Pure function factory (no I/O, no state on disk). Returns a function
that classifies an incoming `(channel, text)`.

```ts
const mention = createMentionFilter({
  botNick: bot.client.nick,
  cooldownMs: 60_000,
});

bot.on("message", (channel, msg) => {
  const m = mention(channel, msg.text);
  if (!m.shouldRespond) return;
  // m.stripped is the text with the @<nick> prefix removed
});
```

Returned classifier signature:

```ts
type MentionResult =
  | { kind: "ignore" }                            // not addressed
  | { kind: "cooldown"; remainingMs: number }     // addressed, but cooled
  | { kind: "respond"; stripped: string };
```

- `addressingStyle?` — defaults to "any" (matches `@nick`, `nick:`,
  `nick,`, or leading-`nick<space>`). swarm-style strict (`nick:`/
  `nick,` only) is opt-in.
- Cooldown is per-channel, in-memory (process-local). Persistence
  isn't needed — the channel-flood scenario the cooldown defends
  against is short-lived.

**Replaces:**
- freeqcc/daemon.ts:417-426 + 463-468 (~30 LOC).
- swarm/ingest.ts:42-72 (the addressing parse — swarm also benefits
  from the cooldown semantics it currently lacks).

### 4. `createTurnGate({ statePath, cooldownMs?, hourlyCap?, cyclePolicy? })`

freeqcc's `gate.ts` re-expressed as a parameterized primitive. Returns
an object with `.evaluate({senderDid, senderNick, now?})` → decision
and `.persist()`.

```ts
const gate = await createTurnGate({
  statePath: "~/.mybot/gate.json",
  cooldownMs: 0,              // no dispatch-to-dispatch wait
  hourlyCap: 30,              // per-bot ceiling
  cyclePolicy: {              // bot↔bot loop detection (opt-in)
    windowMs: 5 * 60_000,
    turnCap: 10,
    backoffMs: 10 * 60_000,
  },
});

const decision = gate.evaluate({ senderDid, senderNick });
if (decision.kind === "silent") return;
if (decision.kind === "refuse") sendRefusal(decision.reason);
// else: dispatch
```

The decision discriminator (`"dispatch" | "refuse" | "silent"`) and
refusal-cooldown semantics carry over from freeqcc unchanged.

State is keyed by sender DID (or `unknown:<nick>` when DID is null), so
the gate composes naturally with `resolveSenderDid`.

**Replaces:**
- freeqcc/gate.ts (181 LOC) with a thin wrapper around the gate
  helper.
- swarm doesn't currently use anything like this; the option to adopt
  it exists but isn't required.

### 5. `createDaemonCLI({ name, runDaemon, doctorChecks?, paths })`

A Commander-based CLI scaffold that wires the five universal daemon
commands. The bot author provides:

- `name` — `"freeqcc"`, `"swarm-coordinator"`, etc.
- `runDaemon: (opts) => Promise<{stop: () => Promise<void>}>` — the
  bot's main entry point. The scaffold owns SIGINT/SIGTERM handling
  and pid-file writes.
- `paths.{daemonPid, daemonLog, agentKey, dir}` — where pid/log/seed
  live for *this* bot.
- `doctorChecks?: DoctorCheck[]` — bot-specific `doctor` checks
  appended to the generic ones (identity exists, delegation valid,
  server reachable, provenance verified).

```ts
const cli = createDaemonCLI({
  name: "freeqcc",
  paths,
  runDaemon: (opts) => freeqccDaemon(opts),
  doctorChecks: [checkClaudeBinary, checkOwnerJson],
});
cli.parse(process.argv);
```

Scaffold-provided commands:

- `launch [--detach]` — start daemon, optionally fork to background
- `stop` — read pid file, SIGTERM, wait for clean QUIT, kill stragglers
- `status` — pid + actor REST query + config summary
- `doctor` — built-in checks + caller's checks
- `tail` — stream daemon log
- `rotate-key` — mint fresh did:key (daemon must be stopped)

Bot-specific commands (`grant`/`revoke` for freeqcc, `summary` for
swarm coordinator, etc.) are added by the caller via the returned
`Command` instance.

**Replaces:**
- The launch/stop/status/doctor/tail/rotate-key portions of
  freeqcc/cli.ts (roughly 200 of its 636 LOC).
- swarm/cli/src/index.ts (21 LOC) gets upgraded from a bare
  dispatcher to a full daemon shell with no marginal effort.

---

## Out of scope

- **Subprocess control sockets / per-action capability tokens** —
  these are tied to freeqcc's claude-subprocess dispatch pattern. A
  bot-kit-level "RPC plane between the daemon and its workers"
  primitive may make sense someday; this proposal isn't the place.
- **Dollar-based budgets** — swarm's `budget.ts` hooks the server-side
  BUDGET endpoint. Generalizing it would mean moving server-aware
  pricing logic into bot-kit, which crosses an abstraction line this
  proposal doesn't want to cross. swarm keeps its own budget code.
- **Refusal audit log** (freeqcc's `audit.ts`, 44 LOC) — too thin to
  warrant a primitive; freeqcc keeps it.
- **Owner config persistence** — freeqcc has `~/.freeqcc/owner.json`
  with a CLI prompt flow; swarm uses YAML with a pre-resolved DID. The
  shapes don't unify cleanly. bot-kit could surface a one-liner
  `resolveOwner(handleOrDid) → {handle, did}` that wraps the existing
  re-exported `fetchProfile`, but it's so thin I'd rather skip it.
- **Server-side governance signal handling** — already exposed by the
  SDK; doesn't need a bot-kit wrapper.

---

## Migration impact

### freeqcc (estimated)

| File / area              | Before        | After                                    |
| ------------------------ | ------------- | ---------------------------------------- |
| `gate.ts`                | 181 LOC       | ~10 LOC (`createTurnGate` config)        |
| `allowlist.ts`           | 131 LOC       | ~20 LOC (`createAllowlist` + loader)     |
| `daemon.ts` DID resolver | ~50 LOC       | 1 call to `bot.resolveSenderDid`         |
| `daemon.ts` mention      | ~30 LOC       | 1 call to `createMentionFilter`          |
| `cli.ts` daemon shell    | ~200 of 636   | ~50 LOC (`createDaemonCLI` config + custom commands) |
| **Net**                  | **~590 LOC**  | **~80 LOC** — ~85% reduction in the shared-primitive surface area |

freeqcc-specific code (~250 LOC of dispatch.ts, control.ts, the
per-action grant matrix, the streaming PRIVMSG/edit dance) is
untouched.

### freeq-swarm (estimated, post-migration to FreeqBot first)

| File / area                                         | Before         | After                                |
| --------------------------------------------------- | -------------- | ------------------------------------ |
| `shared/identity.ts` + `delegation.ts` + `connect.ts` + `announce.ts` | 402 LOC        | 0 (use `FreeqBot.create()`)           |
| `coordinator/dispatcher.ts:64-78` DID + allowlist gate | ~15 LOC        | ~5 LOC (`bot.resolveSenderDid` + `allowlist.has`) |
| `coordinator/ingest.ts:42-72` addressing parse      | ~30 LOC        | ~5 LOC (`createMentionFilter`)        |
| `cli/src/index.ts`                                  | 21 LOC         | ~30 LOC, gains status/doctor/tail/rotate-key |
| **Net**                                             | **~450 LOC**   | **~40 LOC** + new capabilities       |

---

## Open questions

1. **Allowlist data shape** — string array vs object array. Proposed:
   accept both; coerce strings to `{did}`. Open: should there be a
   reserved field name for action grants so freeqcc doesn't have to
   re-invent `actions: string[]` outside the schema?

2. **WHOIS dedup scope** — proposed cache is per-bot. Should it be
   shared across multiple `FreeqBot` instances in the same process?
   (Currently no consumer runs multiple bots in one process; defer.)

3. **CLI scaffold + commander coupling** — Commander is freeqcc's
   choice; swarm uses raw argv switch. Proposed: scaffold uses
   Commander internally; returns the `Command` instance so callers
   can add subcommands. Bots that hate Commander can implement
   `createDaemonCLI` themselves and just consume the underlying
   helpers (`runWithPidFile`, `streamDaemonLog`, etc.) which would
   be exported as a lower tier.

4. **Mention-mode cooldown clock** — in-memory only. If a bot
   restarts mid-cooldown, it loses the state and may respond again
   within the window. Proposed: accept this; the 60s window is short
   enough that the failure mode is "occasional double reply on
   restart," not "spam loop." Persisting would add complexity for
   little gain.

5. **`createDaemonCLI`'s pid-file behavior** — write before launch?
   verify staleness on stop? Same approach freeqcc currently uses.
   Surface as configurable later if a consumer needs different
   semantics.

6. **Phasing** — land all five at once, or stage? Proposed staging:

   - **Phase 1**: `resolveSenderDid`, `createAllowlist`, `createMentionFilter`
     — pure message-handling helpers, smallest API surface, biggest
     immediate win on swarm migration.
   - **Phase 2**: `createTurnGate` — straightforward port of freeqcc's
     gate.ts; lands after phase 1 stabilizes.
   - **Phase 3**: `createDaemonCLI` — most opinionated; biggest API
     surface; needs both consumers to exercise it.

---

## Acceptance criteria

This proposal is done (after implementation) when:

1. Every primitive above is exported from `@freeq/bot-kit` with type
   declarations + JSDoc + a unit test suite.
2. freeqcc compiles against the new bot-kit with the LOC reductions
   in the migration-impact table (within ±20%), all existing
   freeqcc tests pass, and `freeqcc doctor` is green against prod.
3. freeq-swarm migrates to `FreeqBot.create()` and the three Phase-1
   primitives (`resolveSenderDid`, `createAllowlist`,
   `createMentionFilter`); its existing tests pass.
4. bot-kit README documents each primitive with a one-paragraph
   summary + an example.

---

## Why now

Two consumers is the right number to extract a primitive. With swarm
in the picture, bot-kit has actual rather than hypothetical demand:
every primitive in this proposal exists in at least one of the two
consumers, and freeqcc's full set was the working reference for the
identity/delegation/announce extraction that just landed. Waiting for
a third consumer would either delay until something invents the same
thing a third time, or freeze bot-kit at the lifecycle layer
permanently.
