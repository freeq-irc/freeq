# Making handoffs survive a distracted agent

Brief for an agent run, in `~/src/freeq/freeq-pi`.

Three failures, reported from real use: an agent misses an offer the first
time and never revisits it; an agent accepts and then hangs forever; and a
restarted agent has no idea what it was doing. None of them is a model being
dumb — all three are missing mechanism. Read `src/handoff.ts` (the local
materialized view and its doc comment), `extensions/freeq.ts`
(`onHandoffEvent`, `startAssignedWork`, the `/freeq` command switch), and
`src/connection.ts` (`sendAct`, `onActEvent`) before writing anything.

House rules: match the existing comment voice — say *why*, plain sentences,
no changelog bullets. Every behaviour that can refuse or give up says so in
one clear sentence naming the reason. Tests are vitest, colocated as
`*.test.ts`; the suite is 224 green and must stay green. The lifecycle table
in `@freeq/bot-kit` is the authority on legal verbs — never restate it.

Owner's two decisions, already made — implement exactly these defaults:

- **An offer is auto-accepted when the session is idle and the offerer is
  trusted.** Otherwise it queues rather than blocking.
- **Stalled work auto-fails with a reason**, rather than hanging.

## 1. Intake that cannot drop an offer

Today an inbound offer addressed to us goes straight to `ctx.ui.confirm(...)`
— a blocking modal. Nobody at the terminal, or a restart while it is open,
and the offer is gone: the task sits `offered` forever and nothing revisits
it. Replay does not help; the event arrived, we simply dropped it.

Replace with a queue plus a policy:

- **Auto-accept** when `ctx.isIdle()` is true AND the offerer's tier is
  `handoff` or above (`tierAtLeast`). The existing `cfg.autoAccept` list
  stays as an explicit per-DID override that accepts even when busy.
- **Otherwise queue it** — persisted alongside the handoff view so it
  survives a restart — and notify once, naming the id and how to act on it
  (`/freeq accept <id>`). Never a blocking modal; a modal is what loses work.
- **Drain the queue when the session goes idle.** Poll `ctx.isIdle()` on a
  modest timer (5 s is plenty); on the transition to idle, accept the oldest
  queued offer from a trusted offerer.
- **Offers expire.** A queued offer older than `offerTtlSecs` (default 30
  min, configurable) is declined with a reason — an offerer learns quickly
  and can re-offer elsewhere, which is strictly better than silence. Respect
  the task's own `deadline` when it is sooner.
- Untrusted offerers are still ignored entirely, exactly as now.

## 2. A watchdog on accepted work

`startAssignedWork()` sets a presence label, injects a prompt, and ends.
Nothing tracks the work after that, so a wandering model leaves the task
`assigned` until the server's expiry sweep days later.

- Record `startedAt` and `lastProgressAt` per in-flight task.
- **Heartbeat**: every `progressIntervalSecs` (default 120) while a task is
  in flight, emit a `progress` act event with a short note. `progress` is
  additive in the transition table, so this is free observability and the
  offerer can see the work is alive.
- **Stall**: no completion and no model activity for `stallSecs` (default 900)
  → emit `fail` with a reason naming the stall
  (`"no progress for 15m — the session stopped working on it"`), clear the
  work label, and notify. This is the owner's chosen default; do not prompt.
- **Clean shutdown**: on extension teardown, any in-flight task gets a
  `progress` note saying the session is going down, so the record shows why
  it stopped rather than simply going quiet. Do not `fail` on shutdown — a
  restart may resume it (§3), and a false failure is worse than a gap.
- All three timers must be cancelled on teardown and must never fire twice
  for one task.

## 3. Resume — pick up where it left off

There is no resume path at all today. On start the view is loaded and
nothing asks the server what is still ours.

- On connect (and on reconnect), fetch
  `GET /api/v1/actions?assignee=<self did>&state=assigned` from the server's
  HTTP origin (`httpOriginFor(cfg.server)`, as `verifyActEvent` already
  does), reconcile against the local view, and for anything still assigned to
  us re-enter work through `startAssignedWork()` — the same path the live
  route uses, so there is one way to start work, not two.
- The server is the authority here; a local record the server does not list
  is stale and must be reconciled, not trusted.
- Announce the resume in one line per task, so it is visible rather than
  spooky: `freeq: resuming <id> — <title>`.
- Cap it: resume at most `maxResume` (default 3) tasks, oldest first, and say
  plainly if more were skipped.

## 4. Commands

Add to the `/freeq` switch in `extensions/freeq.ts`, each with a usage line
matching the existing style, and each listed in the help output:

| Command | Does |
|---|---|
| `tasks` | what is assigned to me, what is queued/offered, what is open nearby — with ages |
| `resume [id]` | re-enter assigned work; no id = everything, capped as above |
| `accept <id>` | accept a queued or offered task now |
| `decline <id>` | decline it with an optional reason |
| `drop <id> [reason]` | `fail` an in-flight task honestly instead of leaving it hanging |
| `progress <id> <note>` | manual heartbeat |

Ids may be given as the short prefix the notifications print (first 10
chars); resolve a unique prefix, and refuse an ambiguous one by name.

## 5. Config

New keys, all optional with the defaults above, parsed and validated in
`src/config.ts` beside `autoAccept` (unknown keys must not break older
configs, and older configs must keep working untouched):

`autoAcceptWhenIdle` (bool, default true), `offerTtlSecs` (1800),
`progressIntervalSecs` (120), `stallSecs` (900), `maxResume` (3).

## Tests

Extend the existing files rather than inventing new patterns; pure logic
should be pure functions that can be tested without a live connection:

- an offer arriving while busy queues rather than prompting, and is accepted
  on the transition to idle
- an offer from an untrusted DID is ignored, queued or not
- a queued offer past its TTL is declined with a reason
- a stalled task emits exactly one `fail`, with a reason, and never twice
- the heartbeat emits `progress` while in flight and stops on completion
- resume re-enters only tasks the SERVER still lists as assigned to us,
  respects `maxResume`, and is idempotent across two calls
- id-prefix resolution: unique prefix resolves, ambiguous prefix refuses by
  name

## Done means

`npm run build` clean, `npx vitest run` green including the new tests, and a
short note appended to `README.md` describing the new commands and the two
defaults (auto-accept when idle and trusted; auto-fail on stall). Commit in
small commits on a branch `pi-handoff-resilience`, in the house voice. Do not
push.
