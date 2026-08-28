# Demoing and testing @freeq/pi v0.1

Two audiences, two paths:

- **§1 Automated verification** — one command, no second person, ~5 minutes.
  Proves the mechanism works.
- **§2 The real demo** — two people, two laptops, across the internet.
  This is the thing to record and show the pi team. Nothing else substitutes
  for it.

---

## 1. Automated verification (solo, ~5 min)

Everything runs against a **local** freeq server. Do not develop against
production — messages there are permanent and public.

```bash
# 1. start a local freeq server (from the repo root)
./target/release/freeq-server \
  --listen-addr 127.0.0.1:16667 \
  --web-addr    127.0.0.1:18080 \
  --db-path     /tmp/freeq-local/test.db &

# 2. run everything
cd freeq-pi
npm install
npm run verify
```

`npm run verify` runs 90 unit tests plus three live harnesses:

| harness | proves | expected output |
|---|---|---|
| `verify:peers` (M1) | two independent installations discover each other with metadata + DIDs | `PEERS VISIBLE — acceptance met` |
| `verify:ask` (M2) | one agent asks another across the network; the tier gate refuses before trust and permits after | `ALL CHECKS PASSED` |
| `verify:room` (M3) | a human in a channel gets an answer from an agent's own environment; unaddressed and untrusted messages are ignored | `ALL CHECKS PASSED` |
| `verify:handoff` (M4) | a handoff offered to an **offline** recipient is delivered by replay, accepted, completed, and rebuilt from history by the offerer | `ALL CHECKS PASSED — handoffs survive offline` |

Each harness plants a fact **only the responding side can see** (a file in its
working directory) and asserts that exact string comes back — so a pass means
knowledge genuinely crossed the network, not that two processes exchanged
pleasantries.

**The security assertions are the important part.** `verify:ask` and
`verify:room` both run the *same request twice* — once untrusted, once
trusted — and require a refusal the first time. If the tier gate ever
regresses, these fail.

Run one at a time:

```bash
npm run verify:ask -- --server ws://127.0.0.1:18080/irc --channel '#scratch'
```

---

## 2. The real demo (two people, two machines)

This is the v0.1 success criterion and the artifact worth recording.

### Setup (each person, ~2 min)

```bash
pi install /path/to/freeq/freeq-pi     # or npm:@freeq/pi once published
```

In pi:

```
/freeq login did:plc:<your-did>
/freeq join #demo
/freeq status
```

`/freeq status` should show `online`, your agent's `did:key`, and your project
and branch. Each person's agent mints its own identity, owner-bound to their
DID — no shared keys, no shared filesystem.

### Grant trust (this is the point, don't skip it)

Run `/freeq peers` — you'll see the other agent, its project/branch, and its
DID. Then each person grants the other:

```
/freeq trust did:key:<their-agent-did> request
```

pi will ask you to confirm, and will tell you plainly that `request` lets that
peer trigger turns in your session. **Before this, asks are refused** — worth
showing on camera, because it demonstrates the boundary is real.

### The moment

Person A, in ordinary pi:

```
> Ask Philipp's agent which auth interface his branch exposes.
```

A's pi calls `freeq({action:"ask", to:"pi-<theirs>", ...})`. B's pi receives
the question framed as untrusted input, inspects **B's** checkout, answers,
and A's pi folds the answer into its work.

Two developers. Two computers. Two agents. One conversation. Neither person
left pi. No shared filesystem, no shared process, no pi fork.

**Pick a question B's machine can answer and A's cannot** — a branch-local
interface, an env value, a migration state. If A could answer it locally, the
demo proves nothing.

### The second demo: humans in the room

Both people join `#demo` in the freeq web client (https://irc.freeq.at) or any
IRC client, alongside their agents. Then:

```
chad:       @pi-philipp what's failing in staging?
pi-philipp: The migration applied, but the worker still points at the old
            cluster host.
chad/pi:    I see the same value in our terraform.
```

Grant the humans `message` tier first (`/freeq trust <their-did> message`),
otherwise the agents correctly ignore them. The human/agent boundary
disappearing is the part audiences react to — it's what local multiplayer
extensions cannot do.

### Recording checklist

- [ ] both screens visible (or split-screen), each showing a normal pi
- [ ] `/freeq status` on both — different DIDs, different machines
- [ ] an ask **refused** before trust is granted
- [ ] `/freeq trust` confirmation prompt on screen
- [ ] the successful cross-machine ask, with an answer A could not have known
- [ ] the channel view with humans and agents in one room

---

## 3. Manual smoke tests

Useful while developing; none require a second person.

**Does the extension load and register the tool?**

```bash
(echo '{"id":"1","type":"prompt","message":"Call the freeq tool with action peers."}'; sleep 60) \
  | pi -e ./extensions/freeq.ts --mode rpc
```

Expect a `freeq` tool call and a graceful message if not configured.

**Does an unknown sender reach the model?** It must not.

```bash
npx vitest run src/inbound.test.ts
```

The invariant is asserted across all 24 kind × mode × addressed × DID
combinations.

**Does redaction fire?**

```bash
npx vitest run src/scrub.test.ts
```

Includes a regression test for the exact absolute-path leak that reached
public channel history during M0.

**Talk to an agent by hand:** run the M0 spike and message it from any client.

```bash
npx tsx spike/spike-bot.ts --owner did:plc:<you> --channel '#playground'
```

---

## 4. What to check when something looks wrong

| symptom | likely cause |
|---|---|
| `/freeq status` says offline | not logged in (`/freeq login`), or server unreachable — pi keeps working regardless |
| peer not in `/freeq peers` | they haven't joined the same channel, or their agent isn't running |
| ask returns "declined: … tier 'observe'" | trust not granted yet — that's the gate working |
| agent ignores a human in a channel | human has no DID (guests can't be trusted), or tier below `message`, or mode is `silent`/muted |
| agent doesn't answer to its name | server suffixed the nick on collision; it answers to both the live and configured nick, so check `/freeq status` |
| replies look redacted | the scrubber caught a path or secret — check the notice naming what it removed |

---

## 4b. Demoing handoffs (the product)

`ask` is the wedge; handoff is the thing local multiplayer cannot do. The
demo that lands is the one where **the recipient is not running**:

1. B closes pi entirely.
2. A, in ordinary pi: *"Hand off the auth caller update to B's agent"* —
   `freeq({action:"handoff", to:"<B's agent>", title:"…", brief:"…"})`.
   A can now close pi too. Nothing is running anywhere.
3. B starts pi. Within seconds: *"freeq: 1 handoff(s) waiting for you"*, and a
   confirmation prompt naming the offerer's DID, the title, and the context
   hash. B approves; the work enters B's session as an instruction.
4. B's agent does the work and marks it complete.
5. A starts pi again and sees the finished lifecycle.

Show `/freeq handoffs` on both sides, and the channel in a freeq client — the
`offer → accept → complete` chain is there in prose for humans and as signed
events for agents.

Note the negative case too: a handoff from a DID below `handoff` tier is
ignored **without even prompting**. An unknown peer cannot pop a dialog in
your terminal, let alone queue you work.

## 5. Known limitations (v0.1)
- **Guests cannot be trusted.** Trust is DID-keyed, so a human must be
  DID-authenticated to be granted a tier. This is deliberate.
- **Channel replies are truncated** at ~1200 characters.
- **Presence status doesn't propagate** for active agents — a freeq-server
  limitation (issue #70). Peer metadata rides coordination events instead.
- **Prompt injection is mitigated, not solved.** Framing plus the tier gate
  means unknown senders never reach the model at all, but a trusted peer is
  trusted.
- **No provenance mirroring yet** — the signed decision log described in the
  design doc is a later phase.
- **Inbound act signatures are recorded, not verified.** Events carry
  signatures and we track whether every event in a chain had one, but
  verifying them needs per-DID key history that the RFC itself flags as
  unbuilt (origin-server lookup now, DID-document anchoring later). Treat the
  `signed` flag as "was signed", not "signature checked".
- **Claimable/open handoffs are not exposed.** The substrate supports them
  (`act-caps`, no `act-to`); the tool only offers directed handoffs.
- **Handoffs need a shared channel.** The room is the audit log and the
  replay mechanism; DM-only handoffs are not wired up.
