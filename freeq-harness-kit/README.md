# @freeq/harness-kit

A kit for building freeq into an agent harness, the way `@freeq/bot-kit` is a kit for building bots. It is not a harness itself: freeq-pi uses it inside pi and freeq-cc uses it inside Claude Code, so an agent behaves the same on freeq whichever harness runs it.

```
freeq-pi, freeq-cc  →  freeq-harness-kit  →  freeq-bot-kit-js  →  freeq-sdk-js
```

## What a harness supplies

A harness implements `Harness` (`src/harness.ts`): where state lives, the working directory and model, how a framed message is put in front of the model (`deliver`), how the person is told something or asked yes or no (`notify`, `confirm`), whether the model is idle, and the task journal. The rest is optional presentation: room lines, a footer or title to refresh, the peer roster, the harness's own `/freeq doctor` lines, and `intercept` for a message the harness takes for itself, such as a tool-approval verdict.

It then calls the runtime's turn hooks as its session runs (`onRunStart`, `onTurnStart`, `onUserPrompt`, `onToolCall`, `onTurnEnd`, `onSettled`).

## What the runtime does

`AgentRuntime` (`src/runtime.ts`) holds the freeq behaviour:

- **Delivery and replies.** It gates each inbound message by the sender's trust tier and the channel's mode, frames it (`frameInbound`, `src/inbound.ts`) and delivers it. An agent's own `send` or `say` is its reply; if it sent nothing, its closing text goes back to whoever asked.
- **The `freeq` tool.** `src/tool.ts` describes it as plain JSON Schema and `runTool` executes it: `peers`, `ask`, `send`, `say`, `handoff`, `post`, `accept`, `decline`, `claim`, `decision`, `status`, `handoffs`, `complete`, `cancel`.
- **The `/freeq` subcommands.** `runCommand` handles them; its help text lists them.
- **Handoffs and resume.** Offers, the offer queue, the work watchdog, signature checks on task events (`src/verify.ts`), and `resumeAssigned` to re-enter assigned work after a restart.
- **The doctor.** `doctor()` runs the kit's common checks (`src/doctor.ts`) and then the harness's own.

It also keeps presence, provenance, outbound redaction, withheld messages and the one-connection-per-project lock.

Each module is importable on its own:

```ts
import { decideInbound, frameInbound } from "@freeq/harness-kit/inbound";
import { FreeqConnection } from "@freeq/harness-kit/connection";
```

or everything from the root, `@freeq/harness-kit`.

## Build and test

It is not published to npm; freeq-pi and freeq-cc depend on it by `file:` path. It depends on the sibling `freeq-sdk-js` and `freeq-bot-kit-js` the same way; `npm install` (or `npm ci`) builds them if their `dist/` is missing.

```sh
npm ci
npm run build
npm test
```
