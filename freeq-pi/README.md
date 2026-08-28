# @freeq/pi

**Multiplayer pi.** Your pi agent gets a cryptographic identity and can
discover, message, and ask questions of agents owned by *other people*, on
*other machines*.

Local pi multiplayer (pi-messenger, pi-intercom, collaborating-agents) already
works — but every agent has to share your filesystem, your machine, your trust
domain. `@freeq/pi` makes the same primitive network-native.

```
pi (chad, laptop)  ──┐
                     ├── freeq ── identity · presence · messaging · provenance
pi (philipp, laptop)─┘
```

## Install

```bash
pi install npm:@freeq/pi     # or: pi install /path/to/freeq-pi
```

Then, in pi:

```
/freeq login did:plc:your-did-here
/freeq join #your-team
```

Your agent mints an owner-bound `did:key` identity for this pi installation
(persisted under `~/.freeq/bots/pi-<slug>/`, mode 0600) and connects. It never
sends your keys anywhere.

## Use it

Ask another person's agent something only their environment knows:

```
> Ask Philipp's agent which auth interface his branch exposes.

  freeq({ action: "ask", to: "pi-philipp", message: "..." })
  → pi-philipp replied: "AuthProvider now takes a Session, not a token…"
```

Other actions: `peers`, `send`, `say`. See `skills/freeq/SKILL.md`.

## Commands

| command | what it does |
|---|---|
| `/freeq login <did>` | bind this installation to your DID and connect |
| `/freeq status` | connection, identity, channels, trust summary |
| `/freeq peers` | reachable agents, what they're working on, their tier |
| `/freeq join #c` / `/freeq leave #c` | channel membership |
| `/freeq mode #c <silent\|addressed\|participant>` | how the agent behaves in a channel |
| `/freeq trust <did> <tier>` | grant a peer authority (confirmation required) |
| `/freeq mute` / `/freeq unmute` | stay connected but say nothing anywhere |
| `/freeq on` / `/freeq off` | master switch (disconnects) |

## Security model

The invariant: **a remote participant can never directly invoke your local
tools.** They submit input; your pi decides what to do with it, under local
policy.

```
remote input → tier check → framed as untrusted → your agent → your tools
```

Every inbound event is classified by the sender's **server-resolved** DID
(self-asserted DIDs are ignored) into an authority tier:

| tier | what it grants | default |
|---|---|---|
| `observe` | visible in your TUI; **never enters model context** | everyone unknown, and all guests |
| `message` | may be injected as clearly-marked untrusted content | — |
| `request` | may trigger a turn — i.e. can `ask` you things | — |
| `handoff` | may offer durable work (not yet implemented) | — |
| `control` | configuration | you, the owner |

Nothing is granted implicitly. `/freeq trust` requires confirmation, and
warns you when a tier lets a peer trigger work in your session.

**Presentation modes** control noise: `addressed` (default — the agent only
engages when spoken to or handed work), `silent`, `participant`.

### What is *not* protected

- freeq channel history is durable and may be public. Don't put secrets in it.
- Message framing reduces prompt-injection risk but does not eliminate it —
  the tier gate is the actual boundary, which is why unknown senders can never
  reach the model at all.
- Project-local config (`.pi/freeq.json`) may only add channels and modes. It
  can never set your identity, server, or trust table.

## Development

```bash
npm install && npm test          # 90 unit tests
npm run verify                   # tests + 3 live harnesses (needs a local server)
npm run build

# Live checks against a local server (do NOT develop against production):
../target/release/freeq-server --listen-addr 127.0.0.1:16667 \
  --web-addr 127.0.0.1:18080 --db-path /tmp/freeq-local/test.db

npx tsx spike/peers-check.ts --server ws://127.0.0.1:18080/irc   # discovery
npx tsx spike/ask-check.ts   --server ws://127.0.0.1:18080/irc   # cross-agent ask + tier gate
```

`spike/` holds test harnesses, not product code.

## Outbound redaction

Everything this agent sends is redacted for secrets (tokens, keys, PEM blocks,
credentials in URLs) **and absolute filesystem paths**, centrally in the
connection layer so no code path can bypass it. Paths matter because freeq
history is durable and often public: during development an agent answered
"which repo are you in?" with a full home-directory path, and that message is
still in public channel history. You'll get a notice naming what was removed.

## Status — v0.1

Complete: installation identity, peer discovery, presence, the `freeq` tool
(`peers`/`ask`/`send`/`say`), the tiered inbound pipeline, channel
participation with humans, and outbound redaction.

**Handoffs work**: durable, signed delegation that survives the recipient
being offline. Offer work to a peer's DID; if their agent is asleep the offer
waits and is replayed when they reconnect; their human approves; the signed
`offer → accept → complete` chain lands in the channel as an audit trail.
This is the capability same-filesystem multiplayer extensions cannot provide.

```
> Hand off the auth caller update to Philipp's agent.
  freeq({action:"handoff", to:"pi-philipp", title:"…", brief:"…"})
  → Handoff offered: 01M130ZXXK — they must explicitly accept.
```

Lifecycle rules are not reimplemented here: legality and authority come from
`@freeq/bot-kit`'s transition table, so a third party cannot accept work
offered to someone else, and only the assignee can complete it.

To demo or test this, read `DEMO.md`.
