# @freeq/sdk

TypeScript SDK for building [freeq](https://freeq.at) IRC clients, bots, and integrations.

Handles IRC protocol, IRCv3 capabilities, AT Protocol (Bluesky) authentication, and end-to-end encryption — so you can focus on your application logic.

**Framework-agnostic.** No React, no DOM dependencies. Works in browsers, Node.js, Deno, and Bun.

## Install

```bash
npm install @freeq/sdk
```

## Quick Start

```typescript
import { FreeqClient } from '@freeq/sdk';

const client = new FreeqClient({
  url: 'wss://irc.freeq.at/irc',
  nick: 'mybot',
  channels: ['#general'],
});

client.on('message', (channel, msg) => {
  console.log(`[${channel}] ${msg.from}: ${msg.text}`);
});

client.on('ready', () => {
  client.sendMessage('#general', 'Hello from the SDK!');
});

client.connect();
```

## Documentation

Full documentation with examples: **[freeq.at/docs/typescript-sdk/](https://freeq.at/docs/typescript-sdk/)**

Building a bot? See **[`@freeq/bot-kit`](../freeq-bot-kit-js/)** for higher-level wrapping (identity persistence, delegation cert, announce sequence, state-aware heartbeats).

## Features

### Chat
- **Event-driven** — typed events for messages, members, channels, modes, reactions, edits/deletes, pins, and more
- **AT Protocol auth** — SASL ATPROTO-CHALLENGE (PDS session, OAuth, or pure `did:key`) with broker token refresh
- **E2EE** — Double Ratchet for DMs, AES-256-GCM for channels
- **IRCv3** — message-tags, echo-message, CHATHISTORY, batch, away-notify
- **Auto-reconnect** — exponential backoff with automatic channel rejoin
- **Message signing** — Ed25519 per-session signing for non-repudiation; edits, deletes, and reactions are signed, and servers refuse unsigned changes from logged-in senders
- **Profiles** — AT Protocol profile fetching with TTL cache

### Agent protocol (Phases 1–5)
- **Lifecycle** — `registerAgent`, `submitProvenance`, `setPresence`, `sendHeartbeat`, `startHeartbeat`
- **Governance** — typed `governance` event (pause/resume/revoke/approval/budget) + `requestApproval`, `pauseAgent`, `resumeAgent`, `revokeAgent`, `approveAgent`, `denyAgent`
- **Coordination events** — `sendAct` + `actTags` for tasks, `emitEvent` for any other event type, typed `coordinationEvent` inbound. `createTask`, `updateTask`, `completeTask`, `failTask` and `attachEvidence` are deprecated wrappers that send act events
- **Spawning** — `spawnAgent`, `despawnAgent`, `sendAsChild` + `agentSpawned` / `agentDespawned` events
- **Economics** — `submitSpend`, `setBudget`, `requestBudget`
- **Manifest** — `submitManifest` for declaring capabilities and identity metadata

### Other
- **Zero framework deps** — pure TypeScript, no React/Angular/Vue required

## License

MIT
