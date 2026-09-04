# @freeq/pi — backlog

Things asked for or noticed, not yet done. Newest at the top. Each entry says
what exists today so the gap is precise rather than "make it better".

## Richer working status (asked 2026-09-04)

**Ask:** more status info while the agent is working — via AWAY, or
"something cooler".

**Today:** presence rides bot-kit heartbeats as `state` + `status`. The
extension pushes `executing` with a label on every tool call
(`handoff: <title> · bash`), `active` when idle. The macOS client renders it
as `Away · executing: bash` in the roster. Actor class reaches late joiners
via numeric 674 (server) — but the SDK also re-emits 674 as prose, which is
the "logging" wall in the macOS client (separate item below).

**Gap:** the label is a tool *name*, not what the tool is doing. "bash" says
nothing; "running the test suite (2m in)" or "editing connection.ts" would.
There is no notion of progress, elapsed time, or what the agent is *for*
right now beyond the handoff title.

**Sketch:**
- Status carries a short, human phrase the model writes for itself at turn
  start ("looking at why reconnect drops channels"), refreshed per turn, not
  per tool call. Tool calls add a suffix only when long-running.
- Elapsed time on the current step, so a watcher can tell "thinking" from
  "stuck".
- A `working-on` line in `/freeq peers` and in the roster hover, sourced from
  the same field.
- Consider IRCv3 `metadata` for this rather than overloading AWAY — AWAY is
  a boolean with a string attached and clients render it as "not here",
  which is the opposite of what a working agent is.
- "Cooler": the AV tile already renders scene cards; a working agent could
  push a status card to its tile automatically when it is in a call.

## SDK double-emits numeric 674 as prose

`client.ts` `_` fallback treats every numeric in `400..700` as an error
notice, so 674 (actor classes) is emitted twice — once structured, once as a
`ServerNotice` the UI prints verbatim. Exclude numerics that already have a
structured handler; add a test that a vendor numeric never surfaces as text.

## `whois` answers for one session of a multi-session DID

`/api/v1/users/{nick}/whois` resolves one session via `nick_to_session` and
reports only its channels. A DID with several sessions (scripts, reconnects)
gets a per-session view that can say "no channels" while another session is
in the room and talking. Aggregate across `did_sessions`, the way the roster
does.

## A secondary bot-kit session rebinds the installation's nick

Any short-lived process connecting on an installation's `did:key` under a
different nick makes `bind_identity` release the registered nick and claim
the new one. Two throwaway scripts renamed the flagship installation today.
A non-primary session should attach as a sibling without touching the
registration — probably an explicit opt-in on `FreeqBot.create`.

## Delegated access needs a signed cert on the live installation

Shipped server-side; the live agent's cert is unsigned until `/freeq
authorize` is run once. Not a bug — the correct refusal — but the feature is
invisible until that happens.
