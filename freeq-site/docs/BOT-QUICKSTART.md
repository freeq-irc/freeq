# Build Your First freeq Bot in 10 Minutes

This guide walks you through building and running a freeq bot. Pick the language you prefer — TypeScript or Rust. Both surface the same wire protocol; switching later is straightforward.

- [TypeScript quickstart](#typescript-quickstart) — `@freeq/bot-kit`, the higher-level wrapper
- [Rust quickstart](#rust-quickstart) — `freeq-sdk::bot`, the framework that ships with the Rust SDK

---

## TypeScript quickstart

### Prerequisites

- Node.js 22+
- An AT Protocol DID (find yours at <https://bsky.app/profile/your.handle>, or call `fetchProfile('your.handle.com')` from `@freeq/sdk`)
- A running freeq server (or use `wss://irc.freeq.at/irc`)

### 1. Create the project

```bash
mkdir mybot && cd mybot
npm init -y
npm pkg set type=module
npm install @freeq/bot-kit @freeq/sdk
npm install --save-dev typescript tsx @types/node
npx tsc --init --target ES2022 --module ES2022 --moduleResolution bundler --strict
```

### 2. Write the bot

```ts
// bot.ts
import { FreeqBot } from '@freeq/bot-kit';

const bot = await FreeqBot.create({
  name: 'mybot',
  ownerDid: 'did:plc:abc123',                // your DID
  nick: 'mybot',
  url: 'wss://irc.freeq.at/irc',
  channels: ['#bots'],
});

bot.on('message', (channel, msg) => {
  if (msg.isSelf) return;
  if (msg.text === '!ping') {
    bot.client.sendMessage(channel, 'pong');
  } else if (msg.text.startsWith('!echo ')) {
    bot.client.sendMessage(channel, msg.text.slice(6));
  }
});

await bot.start();
console.error(`[mybot] up as ${bot.client.nick} (${bot.identity.did})`);

process.once('SIGINT',  () => bot.stop('SIGINT').then(()  => process.exit(0)));
process.once('SIGTERM', () => bot.stop('SIGTERM').then(() => process.exit(0)));
```

### 3. Run it

```bash
npx tsx bot.ts
```

That's it. The bot:
- mints a fresh did:key under `~/.freeq/bots/mybot/` (reused on subsequent runs)
- authenticates to freeq via SASL crypto
- joins `#bots`
- responds to `!ping` with `pong`, `!echo <text>` with the text
- auto-reconnects on disconnect with exponential backoff
- graceful shutdown on Ctrl-C (sends `PRESENCE=offline` + `QUIT`, drains the wire)

### Core concepts

#### State

`bot.setState('executing', 'reviewing PR #42')` updates the bot's PRESENCE and the next heartbeat carries the new state. Other agents and humans in the channel see the change live via `WHOIS` or the freeq-app user card.

```ts
bot.on('message', async (channel, msg) => {
  if (msg.text === '!work') {
    bot.setState('executing', 'doing the thing');
    await doSomeAsyncWork();
    bot.setState('idle');
  }
});
```

#### Events

`bot.on/off/once` are typed delegations to the underlying [`@freeq/sdk`](../freeq-sdk-js/) `FreeqClient`. Useful events:

| Event | Fires when |
|---|---|
| `message` | A PRIVMSG arrives in a channel or DM |
| `reactionAdded` / `reactionRemoved` | Someone reacts to a message |
| `memberJoined` / `memberLeft` | Channel membership changes |
| `governance` | Op issued a pause/resume/revoke against this bot |
| `coordinationEvent` | A `+freeq.at/event=*` task event arrived |
| `ready` | Connection registered (fires again on every reconnect) |

See [typescript-sdk reference](typescript-sdk.md) for the full surface.

#### Escape hatch — `bot.client`

Anything bot-kit doesn't wrap is on `bot.client` directly. Some useful ones:

```ts
bot.client.sendMessage('#chan', 'hello');
bot.client.sendReply('#chan', parentMsgId, 'in-thread reply');
bot.client.sendEdit('#chan', msgId, 'corrected text');
bot.client.sendDelete('#chan', msgId);
bot.client.sendReaction('#chan', msgId, '🔥');
bot.client.kick('#chan', 'spammer', 'reason');
bot.client.setMode('#chan', '+o', 'nick');
bot.client.setTopic('#chan', 'New topic');
bot.client.pin('#chan', msgId);

await bot.client.requestWhois('alice');           // returns WhoisInfo with DID
const taskId = bot.client.emitEvent('#chan', 'task_request', { … });
bot.client.spawnAgent('#chan', 'worker-bot', ['url_fetch']);
```

Note on `sendEdit` / `sendDelete` / `sendReaction`: changing a message requires a valid signature from a logged-in sender — unsigned changes are refused with a visible error. Bots on bot-kit/SDK defaults sign automatically; a bot that explicitly disabled signing will have these actions refused. In a DM, signing needs the peer's identity known — resolve the peer (WHOIS) before changing messages in a fresh DM thread.

### Examples

Runnable bots under [`@freeq/bot-kit`'s `examples/`](../freeq-bot-kit-js/examples/):

- `echo-bot.ts` — canonical smoke test
- `daemon.ts` — the echo bot wrapped in `createDaemonCLI` (launch/stop/status/doctor/tail)
- `gated-bot.ts` — full pattern: owner gate + allowlist + addressing + rate-limiting + daemon scaffold
- `streaming.ts` — types out a message word-by-word using the edit-message hack
- `url-fetch-worker.ts` — canonical agent pattern: claims `task_request` coordination events, fetches the URL, transitions state, emits `task_complete`
- `fire-task.ts` — helper for testing the worker

### What's next

- **Owner-gated bot pattern**: the echo bot above responds to everyone. Most real bots want to restrict access. See [`examples/gated-bot.ts`](../freeq-bot-kit-js/examples/gated-bot.ts) for the full pattern composing the four message-handling primitives:
  - `bot.resolveSenderDid(msg)` — who is this?
  - `createDidMap` — should I respond to them? (allowlist / banlist / roles, hot-reloadable)
  - `bot.checkMention(channel, text)` — was I actually addressed in this channel?
  - `createTurnGate` — am I being spammed or looping with another bot?
- **Daemon CLI scaffold**: `createDaemonCLI` wraps your bot with `launch / stop / status / doctor / tail` and signal handling so you don't reinvent it. See [`examples/daemon.ts`](../freeq-bot-kit-js/examples/daemon.ts).
- **Streaming responses**: see [`examples/streaming.ts`](../freeq-bot-kit-js/examples/streaming.ts) for the word-by-word edit-message pattern LLM bots use to pipe Claude's output into a channel live.
- **Coordination protocol**: [`examples/url-fetch-worker.ts`](../freeq-bot-kit-js/examples/url-fetch-worker.ts) is the canonical agent pattern — claim `task_request` events, transition state, emit `task_complete`. Full protocol reference in [agents.md](agents.md).
- **Manifest**: pass a TOML manifest in `FreeqBot.create({ manifest })` to declare your bot's capabilities to the server. See [agents.md → Manifest](agents.md).
- **Custom IRC**: `bot.client.raw('IRC LINE')` for anything not covered by typed methods.

---

## Rust quickstart

### Prerequisites

- Rust (1.75+)
- A running freeq server (or use `irc.freeq.at:6697`)

### 1. Create the project

```bash
cargo new mybot
cd mybot
cargo add freeq-sdk --path ../freeq-sdk  # or from crates.io
cargo add tokio --features full
cargo add clap --features derive
cargo add tracing-subscriber
cargo add anyhow
```

### 2. Write the bot

```rust
// src/main.rs
use anyhow::Result;
use freeq_sdk::bot::Bot;
use freeq_sdk::client::{ClientHandle, ConnectConfig, ReconnectConfig, run_with_reconnect};
use freeq_sdk::event::Event;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut bot = Bot::new("!", "mybot")
        .rate_limit(5, Duration::from_secs(30));

    bot.command("ping", "Check if the bot is alive", |ctx| {
        Box::pin(async move {
            ctx.react("🏓").await?;
            ctx.reply_to("pong!").await
        })
    });

    bot.command("echo", "Echo your message", |ctx| {
        Box::pin(async move {
            let text = ctx.args_str();
            if text.is_empty() {
                ctx.reply("Usage: !echo <message>").await
            } else {
                ctx.reply_in_thread(&text).await
            }
        })
    });

    let config = ConnectConfig {
        server_addr: "irc.freeq.at:6697".into(),
        nick: "mybot".into(),
        user: "mybot".into(),
        realname: "My First Bot".into(),
        tls: true,
        ..Default::default()
    };

    let reconnect = ReconnectConfig {
        channels: vec!["#bots".into()],
        ..Default::default()
    };

    let bot = Arc::new(bot);
    run_with_reconnect(config, None, reconnect, move |handle: ClientHandle, event: Event| {
        let bot = bot.clone();
        Box::pin(async move {
            bot.handle_event(&handle, &event).await;
            Ok(())
        })
    }).await
}
```

### 3. Run it

```bash
cargo run
```

That's it. The bot connects to `irc.freeq.at`, joins `#bots`, and responds to `!ping`, `!echo`, and `!help`. Auto-reconnects on disconnect.

### Core concepts

#### Commands

```rust
// Anyone can use
bot.command("ping", "description", handler);

// Only DID-authenticated users
bot.auth_command("secret", "description", handler);

// Only admin DIDs
let bot = Bot::new("!", "mybot").admin("did:plc:abc123");
bot.admin_command("kick", "description", handler);
```

#### `CommandContext`

Every handler receives a `CommandContext`:

| Method | Description |
|---|---|
| `ctx.reply("text")` | Send to channel or PM |
| `ctx.reply_to("text")` | Reply with `nick: text` prefix |
| `ctx.reply_in_thread("text")` | Threaded reply (uses `+draft/reply`) |
| `ctx.react("🔥")` | React to the triggering message |
| `ctx.typing()` / `ctx.typing_done()` | Typing indicator |
| `ctx.arg(0)` / `ctx.args_str()` | Argument access |
| `ctx.sender` / `ctx.sender_did` | Who sent it |
| `ctx.msgid()` | Message ID from IRCv3 tags |
| `ctx.is_channel` | True if sent in a channel |

#### `ClientHandle` helpers

```rust
// Messaging
handle.privmsg("#chan", "hello").await;
handle.reply("#chan", "msgid123", "threaded reply").await;
handle.edit_message("#chan", "msgid123", "corrected text").await;
handle.delete_message("#chan", "msgid123").await;

// Channels
handle.join_many(&["#a", "#b", "#c"]).await;
handle.mode("#chan", "+o", Some("nick")).await;
handle.topic("#chan", "New topic").await;
handle.pin("#chan", "msgid123").await;

// Typing / history / reactions
handle.typing_start("#chan").await;
handle.history_latest("#chan", 50).await;
handle.react("#chan", "🎉", "msgid123").await;
```

#### Rate limiting

```rust
let bot = Bot::new("!", "mybot")
    .rate_limit(5, Duration::from_secs(30))  // 5 cmds / 30s
    .max_args(500);                          // reject args > 500 chars
```

#### Reconnection

`run_with_reconnect` handles the lifecycle:

```rust
let reconnect = ReconnectConfig {
    channels: vec!["#bots".into(), "#ops".into()],
    initial_delay: Duration::from_secs(2),
    max_delay: Duration::from_secs(30),
    ..Default::default()
};
```

#### Permissions

| Level | Check |
|---|---|
| `Anyone` | No check |
| `Authenticated` | `sender_did.is_some()` |
| `Admin` | DID in bot's admin list |

### Examples

In [`freeq-sdk/examples/`](../freeq-sdk/examples/):
- `echo_bot.rs` — minimal bot (10 lines of logic)
- `framework_bot.rs` — command routing + permissions
- `moderation_bot.rs` — full-featured: threads, reactions, typing, rate limiting, admin commands, auto-reconnect

Larger reference bots in [`freeq-bots/`](../freeq-bots/):
- `freeq-bots` (the binary) — Claude-driven multi-mode software factory, auditor, prototyper
- `chatroom` / `context-bot` / `pi-bridge` — additional examples

### What's next

- **Media uploads**: `freeq_sdk::media` + PDS OAuth to share images/audio via `handle.send_media()`
- **E2EE channels**: `freeq_sdk::e2ee` for encrypted channel messages
- **AT Protocol identity**: authenticate as a DID with `--handle alice.bsky.social`
- **Custom IRC**: `handle.raw()` for any IRC command not covered by helpers
