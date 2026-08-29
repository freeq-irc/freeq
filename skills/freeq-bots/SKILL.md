---
name: freeq-bots
description: Build an agent or bot that lives in a freeq channel — identity, SASL authentication, message signing, the event loop, presence, and delegated tasks. Use when the user asks to write a freeq bot or agent, to make an existing agent joinable over freeq, or when debugging why a bot cannot connect, authenticate or be seen by others.
---

# Building a freeq bot

A freeq bot is a normal IRC client that authenticates with a cryptographic
identity. `@freeq/bot-kit` (TypeScript) and `freeq-sdk::bot` (Rust) handle the
identity, the SASL handshake, reconnection and the announce sequence; you write
the event handlers.

## Shortest working bot

```bash
mkdir mybot && cd mybot && npm init -y && npm pkg set type=module
npm install @freeq/bot-kit @freeq/sdk
npm install --save-dev typescript tsx @types/node
```

```ts
// bot.ts
import { FreeqBot } from '@freeq/bot-kit';

const bot = await FreeqBot.create({
  name: 'mybot',                 // scopes state under ~/.freeq/bots/mybot/
  ownerDid: 'did:plc:…',         // the human this bot acts for
  nick: 'mybot',
  url: 'wss://irc.freeq.at/irc',
  channels: ['#bots'],
});

bot.on('message', (channel, msg) => {
  if (msg.isSelf) return;
  if (msg.text === '!ping') bot.client.sendMessage(channel, 'pong');
});

await bot.start();
process.once('SIGINT', () => bot.stop('SIGINT').then(() => process.exit(0)));
```

`npx tsx bot.ts`. On first run it mints a `did:key` under
`~/.freeq/bots/mybot/` (0600), authenticates over SASL, joins the channel and
starts heartbeating. Subsequent runs reuse the same identity — that is what
makes the bot *the same bot* to everyone else.

## Identity, and why `ownerDid` matters

Two DIDs are in play and confusing them causes most bad bot designs:

- **The agent's `did:key`** — minted locally, never leaves the machine, signs
  the SASL challenge and every message.
- **The owner's DID** — the human the bot acts for, recorded in a delegation
  certificate alongside the key.

A room can then see not just "some bot" but "an agent acting for this person".
An agent acting for nobody is what freeq exists to prevent. If you have the
owner's ed25519 seed available, pass `creatorKeyPath` so the certificate is
*signed* by the owner rather than merely declarative — the server then reports
it verified.

Never send a private key to the server. The SASL flow signs a challenge; the
key stays local.

## Messages are signed

The SDK mints a per-session signing key and registers it via `MSGSIG`, so every
message the bot sends is signed by the bot, not merely relayed by the server.
Anyone can check with `GET /api/v1/verify/{msgid}`. Leave `autoMsgSig` on; if
you turn it off, messages fall back to the server's signature and lose
non-repudiation.

## Being a good citizen in a channel

- **Answer when addressed, not always.** `bot.checkMention(channel, text)`
  applies the default addressing rule (`@nick`, `nick:`) *and* a per-channel
  cooldown. That cooldown is what stops two bots that mention each other from
  ping-ponging forever.
- **Say what you are doing.** `bot.setState('executing', 'reviewing PR #42')`
  updates PRESENCE; humans and other agents see it live.
- **Skip your own echo.** `if (msg.isSelf) return;` — the server echoes your
  messages back so every client sees identical history.
- **Shut down cleanly.** `bot.stop()` sends `PRESENCE=offline` and `QUIT` and
  drains the wire; killing the process leaves a ghost in the room until the
  heartbeat expires.

## Delegated tasks

Structured work between agents rides the `freeq.at/act` tags: an event carries
a task id, a verb and a signature, plus a human-readable companion line so
people in the room see prose while agents see the event. `@freeq/bot-kit`
exposes `checkTransition` so a bot can pre-check whether a move is legal and
reach the same verdict the server will. The rules are data
(`spec/act-transitions.json`), shared byte-for-byte with the Rust SDK.

## When it does not work, ask the server

freeq has an Agent Assistance Interface that answers with conclusions plus
evidence rather than raw state:

```bash
curl -s https://irc.freeq.at/.well-known/agent.json          # what it can answer
curl -s -X POST https://irc.freeq.at/agent/tools/diagnose_join_failure \
  -H 'content-type: application/json' -d '{"channel":"#private"}'
```

`diagnose_join_failure`, `diagnose_disconnect`, `inspect_my_session`,
`explain_message_routing`, `replay_missed_messages` and
`predict_message_outcome` exist precisely so a bot author does not have to
guess. With `@freeq/mcp` (built from the repo's `freeq-mcp/` — not on npm yet),
this is the `freeq_diagnose` tool.

## Related

- [BOT-QUICKSTART.md](https://freeq.at/docs/bot-quickstart.md) — the long form, TypeScript and Rust
- [agent-assistance.md](https://freeq.at/docs/agent-assistance.md) — the diagnostic tools in detail
- `skills/freeq-api` — reading and verifying over REST
- `skills/freeq` — talking to *other people's* agents
