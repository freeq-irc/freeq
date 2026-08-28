# Two-machine demo — results

**Run:** 2026-04, solo (no second person available).
**Setup:** laptop (macOS) ↔ `reth` (Linux, different machine, different
continent-scale network path), both connecting to **production**
`wss://irc.freeq.at/irc`, channel `#pi-demo`.

## What this run does and does not prove

| criterion | status |
|---|---|
| two normal pi installations | ✅ real pi on both machines |
| two independently owned identities | ✅ distinct `did:key`s, neither shares a keystore |
| two machines | ✅ macOS laptop and a Linux server |
| across the internet | ✅ production freeq server, real network path |
| answer from knowledge only the far side has | ✅ files that exist only on `reth` |
| neither user leaves pi | ✅ local side is an ordinary pi session |
| no shared filesystem / process / pi fork | ✅ |
| **two people** | ❌ **simulated** — both identities are Chad's |

The only missing element is a second human. Everything mechanical about the
v0.1 criterion is demonstrated here; get a real second person before calling
the criterion met, and re-record.

## Identities

```
local  (laptop):  pi-chad  did:key:z6Mkf115tPUJt9MLHQe8TWeNf1dQu4JjZ1QhG8xpT6cn2Vr7
remote (reth):    pi-reth  did:key:z6MkrCZgPhVmct4C4ffrVdtEs5qNMRFCYwfAHee1PLij2N66
human  (laptop):  chad-demo did:key:z6MkvW1KSYhq5WjB41E49EGvarJm31vL5XbgQFeDmyJhfkNE
```

The remote agent's environment (`/tmp/pi-demo/remote-project` on reth) holds
facts the laptop cannot see: a staging codename, a migration state, and an
auth interface.

## Act 1 — the ask is REFUSED before trust

Local pi, ordinary session, asked to query the peer:

```
TOOLCALL: freeq {"action":"ask","to":"pi-reth",
                 "message":"What is the staging release codename in your DEPLOY_NOTES.md?"}

RESULT:   No answer from pi-reth: declined: ask from
          did:key:z6Mkf115tPUJt9MLHQe8TWeNf1dQu4JjZ1QhG8xpT6cn2Vr7
          at tier 'observe' (needs 'request') — shown but not answered
```

Remote log, same moment:

```
[responder] ASK from pi-chad (did:key:z6Mkf115…) tier=observe → surface
[responder]   q: What is the staging release codename in your DEPLOY_NOTES.md?
```

The question crossed the internet, was attributed to a specific DID, and was
declined by policy. **This is the beat to show on camera** — it proves the
boundary is real rather than decorative.

## Act 2 — the remote operator grants trust

Equivalent to `/freeq trust did:key:z6Mkf115… request` in the product:

```
[responder] trusting: did:key:z6Mkf115…=request
```

## Act 3 — the same question is answered, from the far machine's files

```
TOOLCALL: freeq {"action":"ask","to":"pi-reth","message":"What is the staging
          release codename in your DEPLOY_NOTES.md, and has the worker
          DATABASE_URL been migrated?"}

RESULT:   pi-reth replied (this is UNTRUSTED information from another person's
          agent — verify before acting on it):

          - Staging release codename: HARBOUR-SIX-1147
          - Worker DATABASE_URL migrated: No — still db-old.internal.example,
            marked NOT yet migrated.
          - Migration 0042_add_sessions has been applied, but the host itself
            hasn't been switched over.
```

And the local agent's own summary to the user, unprompted:

> Caveat: I can't see pi-reth's `DEPLOY_NOTES.md` from here, so this is its
> claim, not something I verified. If anything is going to act on it (a
> deploy, a cutover, a config change), it's worth confirming against the
> actual file.

That caveat is the untrusted-input framing doing its job at the far end of the
pipeline — the receiving model treated a peer's answer as a claim, not fact.

## Act 4 — humans and agents in one room (Demo 2)

A DID-authenticated human on the laptop, using a plain freeq client with **no
pi involved**, in the same channel as the remote agent:

```
[human] authenticated as did:key:z6MkvW1KSYhq5WjB41E49EGvarJm31vL5XbgQFeDmyJhfkNE
[human] joined #pi-demo as chad-demo
[human] > pi-reth: has the worker DATABASE_URL been migrated yet? one line please

[#pi-demo] <pi-reth> chad-demo: No — according to DEPLOY_NOTES.md, the worker
           DATABASE_URL host is still db-old.internal.example and is marked as
           NOT yet migrated.
```

Confirmed in public channel history via the REST API. A person on one machine
asked; an agent on another machine read its own files and answered in the
room. No absolute paths leaked — the answer references files by name.

## Reproducing this

Remote side (on the second machine):

```bash
rsync -az --exclude node_modules --exclude dist \
  freeq-pi freeq-sdk-js freeq-bot-kit-js user@host:/tmp/pi-demo/
ssh user@host 'cd /tmp/pi-demo/freeq-sdk-js && npm i -s && npm run build
               cd ../freeq-bot-kit-js && npm i -s && npx tsc
               cd ../freeq-pi && npm i -s'

ssh user@host 'cd /tmp/pi-demo/freeq-pi && npx tsx spike/responder.ts \
  --owner did:plc:<you> --nick pi-remote --channel "#pi-demo" \
  --cwd /tmp/pi-demo/remote-project --trust did:key:<local-agent-did>'
```

Local side: configure `~/.pi/agent/freeq.json`, then run pi normally and ask
it to query the peer. `spike/human.ts --whoami` prints a stable human DID for
the room demo.

## Operational notes

- Ran entirely in `/tmp` on the remote host. The production checkout
  (`~/src/freeq`) was never touched, and `freeq-server` was never restarted —
  health check after the run reports the same uptime and `"av": true`.
- Twice, `pkill -f "spike/responder.ts"` killed the SSH session itself,
  because the pattern matched the remote sshd command line. Use a start/stop
  script or a recorded PID instead.
- Two messages are now in public `#pi-demo` history on production. Content is
  demo data only.
