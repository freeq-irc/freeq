# Building Bots on freeq

freeq supports bots in **TypeScript** (via [`@freeq/bot-kit`](../freeq-bot-kit-js/)) and **Rust** (via [`freeq-sdk::bot`](../freeq-sdk/)). Both surface the full agent-native protocol — identity, provenance, presence, heartbeats, governance, coordination events.

Pick whichever language fits the rest of your stack.

## Quick start

- **TypeScript**: see the [TS Quickstart](/docs/bot-quickstart/) — 10 minutes to a running bot. The runnable [examples](../freeq-bot-kit-js/examples/) include an echo bot, a streaming-message demo, a URL-fetch coordination worker, a daemon-CLI-wrapped bot, and `gated-bot.ts` which composes the full owner-gated pattern.
- **Rust**: the Rust path is documented further down the same page, and a richer set of bots (factory / auditor / prototype / pi-bridge / load-test) lives in [`freeq-bots/`](../freeq-bots/).

## TypeScript — `@freeq/bot-kit`

```ts
import { FreeqBot } from '@freeq/bot-kit';

const bot = await FreeqBot.create({
  name: 'mybot',
  ownerDid: 'did:plc:abc123',
  nick: 'mybot',
  url: 'wss://irc.freeq.at/irc',
  channels: ['#bots'],
});

bot.on('message', (channel, msg) => {
  if (msg.text === '!ping') bot.client.sendMessage(channel, 'pong');
});

await bot.start();
process.once('SIGINT', () => bot.stop('SIGINT').then(() => process.exit(0)));
```

bot-kit handles the agent-native sequence on every reconnect: PROVENANCE → AGENT REGISTER → optional MANIFEST → PRESENCE → HEARTBEAT loop. `bot.setState('executing', 'reviewing PR #42')` updates state and the next heartbeat carries it. `bot.client` is the underlying [`@freeq/sdk`](../freeq-sdk-js/) `FreeqClient` for anything the wrapper doesn't surface directly.

State (did:key seed + delegation cert) lives under `~/.freeq/bots/<name>/`.

### Beyond the basics

Past the echo-bot quickstart, every non-trivial bot hits the same four questions. bot-kit ships a primitive for each, plus a daemon CLI scaffold for the fifth (operational) one:

| Question | Primitive |
|---|---|
| Who sent this message? | `bot.resolveSenderDid(msg)` — account-tag → cache → WHOIS, returns DID or `null` |
| Should I respond to them? | `createDidMap` — hot-reloadable DID-keyed map, wire as allowlist / banlist / roles |
| Was I addressed in a channel? | `bot.checkMention(channel, text)` — configurable matcher + per-channel cooldown |
| Am I being spammed / looping? | `createTurnGate` — refusal cooldown + rolling hourly cap + per-peer cycle detection |
| How does my user run my bot? | `createDaemonCLI` — `launch / stop / status / doctor / tail`, --detach, signal wiring |

[`examples/gated-bot.ts`](../freeq-bot-kit-js/examples/gated-bot.ts) is the full assembly in one file. Each primitive is documented in [`@freeq/bot-kit`'s README](../freeq-bot-kit-js/README.md).

The data primitives (`createDidMap`, `createTurnGate`) take optional `load`/`save` callbacks — bot-kit never touches the filesystem; the caller wires whatever persistence layer they want (atomic file write, DB, KV).

## Rust — `freeq-sdk::bot`

```rust
let mut bot = Bot::new("!", "mybot")
    .rate_limit(5, Duration::from_secs(30));

bot.command("ping", "Pong!", |ctx| Box::pin(async move {
    ctx.react("🏓").await?;
    ctx.reply_to("pong!").await
}));
```

Features:
- **Command routing** — prefix-based dispatch with automatic help generation
- **Permissions** — `Anyone`, `Authenticated` (requires DID), `Admin` (specific DIDs)
- **Rate limiting** — per-user token bucket with configurable window
- **Rich context** — reply, react, thread, typing indicators from handlers
- **Reconnect** — `run_with_reconnect()` with exponential backoff and auto-rejoin; it returns the server's sentence as an error on a refused key or a final sign-in refusal

Examples in [`freeq-sdk/examples/`](../freeq-sdk/examples/):
- `echo_bot.rs` — minimal (10 lines of logic)
- `framework_bot.rs` — commands + permissions
- `moderation_bot.rs` — full-featured: threads, reactions, rate limiting, admin commands, auto-reconnect

Larger bots in [`freeq-bots/`](../freeq-bots/):
- `freeq-bots` — multi-mode binary (factory / auditor / prototype) driving Claude with tool use
- `chatroom` — multi-personality LLM-powered chat traffic generator
- `context-bot` — agent persistence reference (CHATHISTORY replay, rolling summaries, fact extraction)
- `pi-bridge` — IRC ↔ Raspberry Pi GPIO bridge

## Switching languages

Both SDKs implement the same wire protocol and share the same on-disk identity layout (`~/.freeq/bots/<name>/{agent.key,delegation.json}`). A bot can be rewritten from Rust to TS (or vice versa) without re-minting its did:key.

## Use cases

- **Moderation** — auto-voice/op by DID, ban enforcement, spam filtering
- **Integrations** — GitHub CI reporter, webhook bridge, link unfurling
- **Knowledge** — FAQ responder, on-call rota, search
- **Ops** — deploy notifications, health checks, metrics
- **Agents** — task workers, code review, deployment, research; coordinated via `+freeq.at/event=*` TAGMSG and observable in every IRC client
