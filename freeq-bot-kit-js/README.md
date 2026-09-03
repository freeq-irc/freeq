# @freeq/bot-kit

High-level wrapper over [`@freeq/sdk`](../freeq-sdk-js/) for building freeq bots. Owns the boilerplate every bot needs:

- did:key identity persistence (32-byte ed25519 seed at `~/.freeq/bots/<name>/agent.key`, mode 0600)
- `FreeqBotDelegation/v1` cert minting and storage (`~/.freeq/bots/<name>/delegation.json`)
- `FreeqClient` construction with crypto SASL wired from the bot's did:key
- the announce sequence — PROVENANCE → AGENT REGISTER → (optional) AGENT MANIFEST → PRESENCE → HEARTBEAT — re-fired on every reconnect
- state-aware heartbeats: `bot.setState(...)` is the single source of truth for what your bot is doing
- hardened startup: rejects on SASL auth failure, pre-ready disconnect, or timeout

## Install

```bash
npm install @freeq/bot-kit @freeq/sdk
```

## Runnable examples

Six illustrative bots live under [`examples/`](examples/):

- [`echo-bot.ts`](examples/echo-bot.ts) — canonical smoke test; echoes messages, replies `pong` to `!ping`
- [`daemon.ts`](examples/daemon.ts) — the echo bot wrapped in `createDaemonCLI`, with `launch / stop / status / doctor / tail` out of the box
- [`gated-bot.ts`](examples/gated-bot.ts) — owner-gated bot with allowlist, refusal cooldown, channel addressing, and rate-limiting. The full pattern, end-to-end, in one file
- [`streaming.ts`](examples/streaming.ts) — types out a message word-by-word using the edit-message hack
- [`url-fetch-worker.ts`](examples/url-fetch-worker.ts) — the canonical agent pattern: claims open `handoff` offers declaring a `url_fetch` capability, fetches the URL, reports with `complete` or `fail`, transitions state along the way
- [`fire-task.ts`](examples/fire-task.ts) — helper that posts a single open `handoff` offer and exits; pairs with `url-fetch-worker` for end-to-end testing

Run any of them with `npm run example:<name> -- --owner did:plc:<your-did> --channel '#test'`. See [`examples/README.md`](examples/README.md) for the full worker walk-through.

## Quick example

```ts
import { FreeqBot } from '@freeq/bot-kit';

const bot = await FreeqBot.create({
  name: 'echo-bot',                    // → ~/.freeq/bots/echo-bot/
  ownerDid: 'did:plc:abc123',          // your AT Protocol DID
  nick: 'echo-bot',
  url: 'wss://irc.freeq.at/irc',
  channels: ['#bots'],                 // auto-join on connect
});

bot.on('message', (channel, msg) => {
  if (msg.isSelf) return;
  if (msg.text === '!ping') {
    bot.client.sendMessage(channel, 'pong');
  }
});

await bot.start();
console.log(`[${bot.identity.did}] up as ${bot.client.nick}`);

// Wire your own signal handlers — bot-kit doesn't install any.
process.once('SIGINT',  () => bot.stop('SIGINT').then(()  => process.exit(0)));
process.once('SIGTERM', () => bot.stop('SIGTERM').then(() => process.exit(0)));
```

That's it. On first run you'll get a fresh did:key under `~/.freeq/bots/echo-bot/`. Subsequent runs reuse the same identity.

## Building a real bot

The echo example above shows the minimum viable shape: connect, listen, reply. Any bot more serious than that will need answers to four questions:

| Question | What bot-kit gives you |
|---|---|
| **Who sent this message?** | `bot.resolveSenderDid(msg)` — account-tag → cache → WHOIS, returns the sender's DID or `null` for guests |
| **Should I respond to them?** | `createDidMap` — a hot-reloadable, DID-keyed map you can wire as an allowlist, banlist, role registry, anything. Caller-owned persistence |
| **Was I actually addressed (in a channel)?** | `bot.checkMention(channel, text)` — matches `@<nick>` or `<nick>:`/`<nick>,` (configurable matcher), with per-channel cooldown |
| **Am I being spammed / looping?** | `createTurnGate` — refusal cooldown, rolling hourly cap, per-peer cycle detection. Caller-owned persistence |

And one operational question:

| Question | What bot-kit gives you |
|---|---|
| **How does my user run my bot?** | `createDaemonCLI` — Commander-based scaffold for `launch / stop / status / doctor / tail`, with --detach forking, pid file management, and signal wiring |

These five primitives compose into the canonical owner-gated bot pattern. The full assembled version is [`examples/gated-bot.ts`](examples/gated-bot.ts); here's the sketch:

```ts
const allowlist = await createDidMap<AllowEntry>({ load: {...}, save: writeFileAtomic(...) });
const gate      = await createTurnGate({ load: ..., save: writeFileAtomic(...) });
const bot       = await FreeqBot.create({ name, ownerDid, nick, url, channels });

bot.on('message', async (channel, msg) => {
  if (msg.isSelf) return;

  // Channel? Only handle when addressed.
  const text = channel.startsWith('#')
    ? (() => {
        const m = bot.checkMention(channel, msg.text);
        return m.kind === 'respond' ? m.stripped : null;
      })()
    : msg.text;
  if (text === null) return;

  // Who's this?
  const senderDid = await bot.resolveSenderDid(msg);

  // Is this allowed? Caller policy: owner OR allowlisted.
  const isAllowed = senderDid && (senderDid === ownerDid || allowlist.has(senderDid));

  // Run it through the rate-limit gate.
  const decision = gate.evaluate({
    senderDid, senderNick: msg.from,
    refusalReason: isAllowed ? undefined : 'not on allowlist',
    skipCycleDetection: senderDid === ownerDid,  // owners aren't bots
  });

  if (decision.kind === 'silent') return;
  if (decision.kind === 'refuse') return bot.client.sendMessage(replyTarget, decision.reason);
  // ...do the work, then await gate.persist()...
});

await bot.start();
```

The bot reads the sender, checks policy, runs the gate, and dispatches — three small choices in a row. Each primitive is documented in detail in the API section below, but this is the rhythm.

## API

### `FreeqBot.create(options)`

Async factory. Loads/creates identity + delegation cert from disk, constructs a `FreeqClient` with crypto SASL, and returns a ready-to-`start()` bot.

```ts
await FreeqBot.create({
  // Required
  name: string,              // scopes state under ~/.freeq/bots/<name>/
  ownerDid: string,          // 'did:plc:…' — caller resolves Bluesky handles themselves
  nick: string,              // IRC nickname
  url: string,               // WebSocket URL, e.g. 'wss://irc.freeq.at/irc'

  // Optional
  root?: string,             // override parent dir (default: ~/.freeq/bots)
  actorClass?: 'agent' | 'external_agent' | 'human',  // default 'agent'
  initialState?: string,     // default 'active'; carried by heartbeats until setState
  initialStatus?: string,    // optional initial PRESENCE status string
  manifest?: string,         // TOML manifest. If set, announce includes AGENT MANIFEST.
  channels?: string[],       // auto-join on connect (forwarded to SDK)
  heartbeatMs?: number,      // default 30_000
  heartbeatTtlS?: number,    // default 60
  serverOrigin?: string,     // REST API origin (default: derived from url)
  onNickCollision?: 'refuse' | 'auto-suffix' | 'random-suffix',  // default 'refuse'
});
```

Caller resolves the `ownerDid`. If you have a Bluesky handle, bot-kit re-exports `fetchProfile` so you can resolve it without a separate `@freeq/sdk` import:

```ts
import { fetchProfile, FreeqBot } from '@freeq/bot-kit';

const { did: ownerDid } = await fetchProfile('alice.bsky.social');
const bot = await FreeqBot.create({ ownerDid, ... });
```

### `bot.start({ timeoutMs? })`

Connects, awaits `'ready'`, runs the announce sequence, starts the heartbeat loop. Resolves once announced.

Rejects with a typed error on:
- SASL auth failure → `SASL auth failed: …`
- Pre-ready disconnect → `disconnected before ready`
- Timeout (default 30s) → `timeout waiting for ready (Nms)`

### `bot.stop(reasonOrOptions?)`

Graceful shutdown. Stops the heartbeat loop, sends `PRESENCE :state=offline` and `QUIT :<reason>`, waits for the WebSocket send buffer to drain (default 2000ms), then disconnects. Idempotent.

```ts
await bot.stop();                                  // default reason
await bot.stop('SIGINT');                          // string shorthand
await bot.stop({ reason: 'redeploy', drainMs: 500 });
```

**Server-side ghost period (~30s).** The freeq server applies a 30-second grace window to DID-authenticated sessions on disconnect — channel membership is held briefly so a quick reconnect doesn't churn JOIN/QUIT messages. To other clients in the channel this looks like the bot lingering after shutdown. It's intentional. If you watch via the freeq-app web client, the bot will visibly disappear ~30s after `bot.stop()` resolves. Heartbeat-TTL-only cleanup (when the QUIT never reaches the server) extends this to ~60-90s.

### `bot.setState(state, status?, task?)`

Updates the bot's current state. Sends an immediate `PRESENCE` update; subsequent heartbeats carry the new state.

```ts
bot.setState('executing', 'reviewing PR #42');
// ... do work ...
bot.setState('idle');
```

Valid states: `online`, `idle`, `active`, `executing`, `waiting_for_input`, `blocked_on_permission`, `blocked_on_budget`, `degraded`, `paused`, `sandboxed`, `revoked`, `offline`.

Read current state via `bot.state` (the last value set).

### `bot.resolveSenderDid(msg, opts?)`

Resolve the DID of an incoming PRIVMSG's sender. Returns `Promise<string | null>` — `null` means "the server has no DID for this sender" (typically a guest, but could also be SASL'd user without `account-tag` whose WHOIS times out).

```ts
bot.on('message', async (channel, msg) => {
  const senderDid = await bot.resolveSenderDid(msg);
  if (!senderDid) return;                          // guest, not authenticated
  if (senderDid !== ownerDid) return;              // not the owner — ignore
  // ...handle owner message...
});
```

Sources, in priority order:

1. **`msg.tags.account`** — server attaches via the `account-tag` capability when the sender is SASL-authed. Authoritative for that exact message; never stale.
2. **nick→DID cache** — populated by the SDK's `memberDid` events (which fire when a WHOIS reply includes a DID). Invalidated on `userRenamed` and `userQuit` events and by a TTL (5 min default).
3. **WHOIS round-trip** — `WHOIS <nick>`, raced against `timeoutMs` (default 3000ms). Concurrent calls for the same nick share one in-flight request.

**`opts`:**

```ts
interface ResolveOpts {
  timeoutMs?: number;   // per-call WHOIS timeout override
  cache?: boolean;      // default true; false = fresh lookup, no cache
  whois?: boolean;      // default true; false = no round-trip
}
```

Three useful combinations:

| `cache` | `whois` | Behavior |
|---|---|---|
| `true` (default) | `true` (default) | account-tag → cache → WHOIS |
| `false` | `true` | account-tag → WHOIS every call (no stale-cache risk; one round-trip per non-tag message) |
| `false` | `false` | **strict mode** — account-tag only. Returns `null` for everyone else. Right call for security-sensitive paths. |

The fourth combination (`cache: true, whois: false`) exists too: cache-only with no round-trips. Useful when you want a best-effort answer without paying for a WHOIS.

**Cache safety.** IRC only broadcasts NICK/QUIT to clients sharing a channel with the user. Bots that know a user only via DM may miss the invalidation event for that user. The TTL is the safety net (caps staleness regardless), and `account-tag` always wins over the cache (so a re-authenticated user is always identified correctly). For security-sensitive paths where you can't tolerate any stale-DID risk at all, use strict mode.

**Resolver tuning at construction time.** Defaults can be set on the bot:

```ts
const bot = await FreeqBot.create({
  ...,
  senderDidResolver: { timeoutMs: 5000, cacheTtlMs: 60_000 },
});
```

Per-call `opts.timeoutMs` overrides for a single resolution.

### `bot.checkMention(channel, text)`

Classify a channel message as addressed-to-this-bot. Returns one of three results:

```ts
type MentionResult =
  | { kind: 'ignore' }
  | { kind: 'cooldown'; remainingMs: number }
  | { kind: 'respond'; stripped: string };
```

The bot reads its own nick live, so server-side renames are picked up automatically. Per-channel cooldown stops the bot from replying to a flurry of @-mentions in the same channel.

```ts
bot.on('message', (channel, msg) => {
  if (msg.isSelf) return;
  const m = bot.checkMention(channel, msg.text);
  if (m.kind !== 'respond') return;
  // m.stripped: the message text with the addressing prefix removed
  bot.client.sendMessage(channel, `${msg.from}: I heard you say "${m.stripped}"`);
});
```

**Default matcher** triggers when:
- `@<nick>` appears anywhere, preceded by start-of-string or whitespace, with `<nick>` as a complete word — so `email@nick.com` doesn't match.
- `<nick>:` or `<nick>,` appears anywhere, preceded by start-of-string or whitespace, with `<nick>` as a complete word.

Bare `<nick>` as a standalone word with no `@` or punctuation does **not** trigger — third-person references like "I'll ask yokota about it" are conversation *about* the bot, not addressing it.

**Override the matcher** at construction:

```ts
const bot = await FreeqBot.create({
  ...,
  mention: {
    cooldownMs: 60_000,                     // per-channel cooldown; default 60_000; set to 0 to disable
    matcher: (text, nick) => {              // optional — defaults to the rule above
      // Return the stripped text on a match, null to ignore.
      const m = /^@?(\S+?)[:,]?\s+(.*)$/s.exec(text);
      if (!m || m[1]!.toLowerCase() !== nick.toLowerCase()) return null;
      return m[2]!;
    },
  },
});
```

The matcher is the policy; bot-kit owns the mechanism (live nick read + per-channel cooldown). Callers who want to compose with the default can import it:

```ts
import { matchMention } from '@freeq/bot-kit';

const bot = await FreeqBot.create({
  ...,
  mention: {
    matcher: (text, nick) => {
      // Use the default, but also accept "/hi <nick>" as an alternate trigger.
      const m = matchMention(nick, text);
      if (m) return m.stripped;
      const slash = new RegExp(`^/hi\\s+${nick.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b\\s*(.*)$`, "i").exec(text);
      return slash ? (slash[1] ?? "") : null;
    },
  },
});
```

### Events

`bot.on(event, handler)`, `bot.off(...)`, `bot.once(...)` are typed delegations to `bot.client.on/off/once`. Subscribe to any event from `FreeqEvents`:

```ts
bot.on('message',       (channel, msg) => { /* ... */ });
bot.on('memberJoined',  (channel, member) => { /* ... */ });
bot.on('governance',    (signal) => { /* react to pause/resume/revoke */ });
bot.on('coordinationEvent', (event) => { /* react to delegation_notice etc */ });
```

### Properties

```ts
bot.client      // FreeqClient — escape hatch for anything not on the wrapper
bot.identity    // { did, didKey, isFresh } — your did:key identity
bot.delegation  // FreeqBotDelegation/v1 cert
bot.stateDir    // absolute path: ~/.freeq/bots/<name>/
bot.state       // current PRESENCE state (string)
```

`bot.client` is fully available for anything the wrapper doesn't surface: `bot.client.sendMessage(...)`, `bot.client.requestWhois(...)`, `bot.client.spawnAgent(...)`, etc. See the [SDK reference](../freeq-site/docs/typescript-sdk.md) for the full surface.

## Daemon CLI scaffold

For long-running bot daemons, `createDaemonCLI` wires the universal commands (`launch`, `stop`, `status`, `doctor`, `tail`) over a [Commander](https://www.npmjs.com/package/commander) program. The bot supplies a `runDaemon` callback; bot-kit handles pid files, `--detach` forking, signal wiring, and the built-in doctor checks (identity, delegation, server actor record).

```ts
import { createDaemonCLI } from '@freeq/bot-kit';

const cli = createDaemonCLI({
  name: 'mybot',
  paths: {
    dir:        '~/.mybot/',
    daemonPid:  '~/.mybot/daemon.pid',
    daemonLog:  '~/.mybot/daemon.log',
    agentKey:   '~/.mybot/agent.key',
    delegation: '~/.mybot/delegation.json',
  },
  // Pre-launch hook (prompts, config persistence). Runs in BOTH the
  // foreground and the detached child — must be idempotent.
  preflight: async (parsed) => {
    const owner = await loadOrPromptOwner();
    return { ownerDid: owner.did, nick: parsed.nick ?? 'mybot' };
  },
  // The daemon entry point. Only runs in the daemon process.
  runDaemon: async (opts) => {
    const bot = await FreeqBot.create({ ...opts, url: 'wss://irc.freeq.at/irc' });
    bot.on('message', (ch, msg) => bot.client.sendMessage(ch, `echo: ${msg.text}`));
    await bot.start();
    return { stop: (reason) => bot.stop(reason) };
  },
  // Extra `launch` flags. Caller reads via parsed.<flag> inside preflight.
  launchOptions: [
    { flags: '--nick <nick>', description: 'Override the bot nick' },
  ],
  // Server actor URL — enables provenance check in `status` + `doctor`.
  actorStatusUrl: (did) => `https://irc.freeq.at/api/v1/actors/${encodeURIComponent(did)}`,
  // Optional bot-specific doctor checks, appended after built-ins.
  doctorChecks: [
    { name: 'claude binary', run: async () => {
        try { execSync('which claude', { stdio: 'pipe' }); return { ok: true }; }
        catch { return { ok: false, reason: 'claude not on PATH' }; }
    }},
  ],
});

// Add custom subcommands on top.
cli.command('grant <did> <action>').description('Grant access').action(/* ... */);

await cli.parseAsync(process.argv);
```

**Built-in `doctor` checks:** identity file (32-byte ed25519 seed → did:key), delegation cert (parses + `bot_did === agent.did`), server actor record (if `actorStatusUrl` provided, queries `online` + `provenance.verified`). Each `doctorChecks` entry runs after, in registration order, with `{ ok: true, detail? } | { ok: 'warn', reason } | { ok: false, reason }`. Doctor exits 1 if any check fails (warnings don't fail).

**Two-callback launch model:** `preflight` runs in foreground (prompts ok) and re-runs idempotently in the detached child after fork. `runDaemon` only runs in the daemon process and receives `preflight`'s return value. Signal handlers (SIGINT/SIGTERM) are wired by the scaffold; the returned handle's `stop(reason)` is invoked on shutdown.

## DID maps (allowlists, banlists, roles, tiers)

`createDidMap` is a hot-reloadable, DID-keyed map. The canonical use is an **allowlist** — the set of DIDs your bot will respond to — but the same primitive backs banlists, role registries, tier flags, friends lists, or any other DID-keyed collection. The framework owns the mechanism (load, watch, atomic in-memory swap, parse-error retention, change notify). The caller owns the meaning.

### Allowlist (the canonical use case)

```ts
import { createDidMap } from '@freeq/bot-kit';

interface AllowEntry { did: string; label?: string; }

const access = await createDidMap<AllowEntry>({
  load: {
    path: '~/.mybot/allowlist.json',
    parse: (raw) => (JSON.parse(raw) as { allowed: AllowEntry[] }).allowed ?? [],
  },
});

bot.on('message', (channel, msg) => {
  if (msg.isSelf) return;
  if (!access.has(msg.senderDid)) return;     // silent ignore for non-allowed
  // ... handle the message ...
});
```

That's it. The file at `~/.mybot/allowlist.json` is `mtime`-polled (default every 2s); operator edits (via a CLI, hand-edits, or deploy) are picked up live with no restart. ENOENT means empty allowlist. Half-written or invalid JSON during a reload is logged as a warning and the previous good state is retained — so a typo doesn't silently wipe all your grants.

### Banlist

Same primitive, opposite wiring:

```ts
const banned = await createDidMap({ load: { path: '~/.mybot/banlist.json', parse: JSON.parse } });

bot.on('message', (channel, msg) => {
  if (banned.has(msg.senderDid)) return;      // silent drop
  // ...
});
```

### Tiered access (one map, two checks)

```ts
interface Entry { did: string; tier: 'basic' | 'sensitive'; }

const access = await createDidMap<Entry>({
  load: { path: '~/.mybot/access.json', parse: JSON.parse },
});

bot.on('command', (msg) => {
  if (!access.has(msg.senderDid)) return refuse('not allowed');
  if (isSensitive(msg.command) && access.get(msg.senderDid)?.tier !== 'sensitive') {
    return refuse('basic tier — sensitive commands require upgrade');
  }
  run(msg.command);
});
```

### Roles / capability flags

```ts
interface Entry { did: string; roles: string[]; }
const roles = await createDidMap<Entry>({ load: { path: 'roles.json', parse: JSON.parse } });

if (roles.get(senderDid)?.roles.includes('moderator')) { /* ... */ }
```

### API

```ts
createDidMap<T extends { did: string }>(opts): Promise<DidMap<T>>
```

**`load`** — discriminated source, three variants:

```ts
// File-backed (mtime-poll auto-watches)
load: { path: string; parse: (raw: string) => T[] }

// Async loader (DB, env, fetch, anything else)
load: async () => myDb.query('SELECT did, tier FROM users')

// Static array (tests, hard-coded lists)
load: [{ did: 'did:plc:alice' }, { did: 'did:plc:bob' }]
```

**`save`** — optional persist callback. **If provided, the returned object is mutable** (has `set` / `delete`); if omitted, it's read-only (compile-time, no runtime checks needed). Caller owns write semantics — for a file you want atomic write (tmp + rename) so a crash mid-write never leaves a half-truncated file for the watcher to choke on. The [`write-file-atomic`](https://www.npmjs.com/package/write-file-atomic) package does this; `db.replaceAll(entries)` / `kv.set('access', entries)` are the equivalents for other backends.

**`pollMs`** — file-source poll interval. Default `2000`. Ignored for function/array sources.

**Returned object:**

```ts
interface DidMapReadOnly<T> {
  has(did: string): boolean;
  get(did: string): T | null;
  list(): T[];                          // snapshot copy
  reload(): Promise<void>;              // force re-read; no-op for arrays
  onChange(cb: (entries: T[]) => void): () => void;   // returns disposer
  close(): void;
}

interface DidMapMutable<T> extends DidMapReadOnly<T> {
  set(entry: T): Promise<void>;         // upsert by DID; awaits save first
  delete(did: string): Promise<boolean>; // returns false if did wasn't present
}
```

### When `save` is and isn't needed

`save` is **only** called when the bot's own code invokes `map.set(...)` or `map.delete(...)`. Omit it when:

- The file is managed externally (operator-edited, written by a separate CLI subcommand, deploy pipeline).
- The bot reads from a DB but writes happen elsewhere (admin UI, API, cron).
- The map is a test fixture or hard-coded list.
- You want grants that don't survive restart (rare but valid).

Provide `save` when you want **in-band mutation**: a `!grant @alice` DM command handler, a `!ban @bob` in-channel moderator action, a time-based expiry sweeper, etc.

```ts
// Owner-dynamic !grant flow
const access = await createDidMap<Entry>({
  load: { path: 'access.json', parse: JSON.parse },
  save: async (entries) => atomicWriteJson('access.json', { entries }),
});

bot.on('dm', async (msg) => {
  if (msg.from !== ownerDid) return;
  if (msg.text.startsWith('!grant ')) {
    const did = await resolveHandle(msg.text.slice(7));
    await access.set({ did, tier: 'basic' });
    bot.reply(msg, `granted ${did}`);
  }
});
```

### Failure modes

| Situation | Behavior |
|---|---|
| File missing on initial load (file source) | Empty map, no error |
| File deleted after start | Map becomes empty, `onChange` fires with `[]` |
| File present but `parse` throws on init | `createDidMap` rejects — bot can't start with unknown state |
| `parse` throws on a reload | Previous state retained, warning logged, polling continues |
| `save` throws | `set`/`delete` rejects; in-memory state unchanged |
| Function `load` throws on init | `createDidMap` rejects |
| Function `load` throws on `.reload()` | Reload rejects, previous state retained |

### Composition: allowlist + banlist (deny wins)

```ts
const allowed = await createDidMap({ load: { path: 'allowed.json', parse: JSON.parse } });
const banned  = await createDidMap({ load: { path: 'banned.json',  parse: JSON.parse } });

function classify(did: string): 'banned' | 'unknown' | 'ok' {
  if (banned.has(did)) return 'banned';
  if (!allowed.has(did)) return 'unknown';
  return 'ok';
}
```

Two instances, two files, caller composes the policy. The framework takes no position on which list "wins" — that's wiring.

## Rate-limit + cycle-detection gate

`createTurnGate` decides, per incoming request, whether your bot should dispatch, refuse, or stay silent. Three layered rules:

- **Dispatch-to-dispatch cooldown** — at most one dispatch every `cooldownMs`. Off by default; LLM latency is its own rate limiter, and chat bots usually don't need an extra brake.
- **Rolling hourly cap** — at most `hourlyCap` dispatches in any 60-minute window. Default 30. A burst is fine, but a chatty user can't burn the bot's whole budget.
- **Per-peer cycle detection** — if the same sender DID back-and-forths more than `cyclePolicy.turnCap` times within `cyclePolicy.windowMs`, force a `cyclePolicy.backoffMs` silence on that peer. Default 10 turns in 5 minutes triggers a 10-minute silence. Stops two bots from spinning in a feedback loop.

The gate also handles **refuse-once-then-silent**: if the caller wants to reject a sender (not on the allowlist, etc.), pass `refusalReason` to `evaluate`. The gate returns `refuse(reason)` the first time, then `silent` for the next hour so the bot doesn't repeat itself.

Who's allowed is the caller's call — the gate doesn't have an allowlist. Compose with `bot.resolveSenderDid` + a `createDidMap` to make that decision before calling `evaluate`.

### API

```ts
import { createTurnGate } from '@freeq/bot-kit';

const gate = await createTurnGate({
  cooldownMs: 0,                 // dispatch-to-dispatch; default 0 (off)
  hourlyCap: 30,                 // rolling 60-min; default 30
  refusalCooldownMs: 60 * 60_000, // per-sender; default 1 hour
  cyclePolicy: {                 // per-peer loop detection; default {5min, 10, 10min}
    windowMs: 5 * 60_000,
    turnCap: 10,
    backoffMs: 10 * 60_000,
  },
  // Persistence is opt-in — same pattern as createDidMap. bot-kit
  // never touches the filesystem. Omit both for in-memory mode.
  load: async () => readJson('~/.mybot/gate.json'),
  save: async (state) => writeFileAtomic('~/.mybot/gate.json', JSON.stringify(state)),
});

// On every inbound message:
const decision = gate.evaluate({
  senderDid: did,             // string | null
  senderNick: msg.from,
  refusalReason: isAllowed ? undefined : 'not on allowlist',
  skipCycleDetection: did === ownerDid,  // owners can be chatty without tripping
});

if (decision.kind === 'silent') return;
if (decision.kind === 'refuse') return refuse(decision.reason);
// decision.kind === 'dispatch' — do the work

// Persist whenever — typically after a dispatch / refusal:
await gate.persist();
```

### Mode comparison

| Setup | Default | Effect |
|---|---|---|
| In-memory only | omit `load` and `save` | State resets on daemon restart; refusal cooldowns lost, hourly cap counter resets |
| Load only | `load` set, `save` omitted | Restore from prior state at startup; mutations don't write back |
| Persisted | both `load` and `save` set | Caller chooses the write path (atomic file write, DB, etc.); state survives restarts |

`evaluate` is synchronous and mutates internal state. `persist` is async and just serializes the current state through the configured `save`. There's no auto-persist — caller decides when to write (after each evaluate, on a timer, on shutdown).

### When `skipCycleDetection` matters

A human owner DM-chatting with the bot at 30-second intervals would hit the default cycle detection (10 turns in 5 minutes) and get silenced. Pass `skipCycleDetection: true` for the owner — they're not a bot, they shouldn't trip a bot-loop detector.

## What this package does NOT do

Deliberately out of scope:

- **Policy decisions.** `createDidMap` is a hot-reloadable DID-keyed map; `createTurnGate` runs rate-limit + cycle detection. Bot-kit takes no position on what membership means (allow / ban / role) or who counts as "owner" — those are caller wiring, not framework behavior.
- **Persistence layer.** Both `createDidMap` and `createTurnGate` take optional `load` / `save` callbacks. Bot-kit never touches the filesystem; callers wire `write-file-atomic`, a DB, or whatever they need.
- **Signal handlers (when not using `createDaemonCLI`).** `process.on('SIGINT', ...)` is process-global; if you're using `FreeqBot` directly without the CLI scaffold, the application owns it. The README's quick example shows the snippet.
- **Reconnect logic.** Already in the SDK transport (`@freeq/sdk`'s `Transport` does exponential-backoff auto-reconnect and re-emits `'ready'` on resume). Bot-kit's announce loop is already bound to every `'ready'` so reconnects re-announce automatically.
- **did:key rotation.** No `rotate-key` command shipped. Bot-kit *could* generically delete `agent.key` + `delegation.json` and let the next launch mint fresh ones, but in practice rotation always means more than that — freeqcc, for example, also needs to wipe per-DID claude session caches. So we leave it to the bot to add a `rotate-key` subcommand on the `Command` returned by `createDaemonCLI`, with whatever extra cleanup it needs.
- **Manifest building.** The announce sequence includes `AGENT MANIFEST :<toml>` if you pass a `manifest` string to `FreeqBot.create`. Bot-kit doesn't compose the TOML for you — actor_class, capabilities, supported intents, and version strings are all per-bot, so we accept a pre-formatted string and pass it through. Use any TOML library; see [agents.md](../docs/agents.md) for the manifest schema.

## Status

v0.2 — five primitives in: `FreeqBot`, `createDaemonCLI`, `createDidMap`, `bot.resolveSenderDid`, `bot.checkMention`, `createTurnGate`. Used in production by `freeqcc`; `freeq-swarm` migration planned.
