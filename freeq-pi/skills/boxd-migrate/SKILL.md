---
name: boxd-migrate
description: Move this pi session onto a boxd.sh cloud VM so it keeps running as an agent on freeq — with its own did:key, claimed by the owner as one of their agents, and a channel to join. Use when the user says "migrate this session to boxd", "put this agent on a VM", "run this session in the cloud", or asks for an always-on agent in a freeq channel.
---

# Migrating a pi session to a boxd VM

The end state: a boxd VM running pi in tmux, resuming this conversation's
history, connected to freeq under **its own** `did:key`, delegated by the
user's DID, sitting in a channel the user named.

## The one thing that is not file copying

Everything else is transfer. This is the part to get right:

- **The VM mints its own agent key.** Copying `~/.freeq/bots/<name>/agent.key`
  from the laptop would put one DID on two machines — not redundancy, a broken
  participant, with two sessions fighting over one nick.
- **Nothing of the owner's goes to the VM.** The VM's certificate names the
  owner and is not signed. The owner claims the VM's DID from their own
  device: an `at.freeq.agentKey` record in their account, written in the freeq
  web app (Settings → Agents → + Add an agent) or with
  `freeq-bot-id register --owner <handle> <did>`.
- **An unproven certificate grants nothing.** `#channel` with `+i` admits an
  agent only on a *verified* delegation whose owner is present in the channel
  or is its founder/DID-op (`freeq-server/src/connection/channel.rs` —
  "an agent may go where the person it acts for already is"). The server
  verifies the certificate when it finds the owner's record naming the agent.

So the chain is: VM mints its did:key → owner adds that DID as one of their
agents → the agent connects, the server reads the record and verifies →
channel opens. A record the owner removes ends it within the hour.

## Do it

From the project directory being migrated, with `@freeq/pi` installed:

```bash
<freeq-pi>/scripts/boxd-migrate.sh --vm my-box --channel '#my-room'
```

Defaults: VM `pi-<project>`, channel = first in `~/.pi/agent/freeq.json`, nick
= local nick + `-boxd`, session = `$PI_SESSION_FILE`. `--dry-run` prints the
plan; `--no-start` provisions without launching pi; `--session none` starts the
remote agent with no history.

The script is idempotent — re-running against an existing VM reuses the
machine, the key, and a cert that is already signed.

What it does, in order: create the VM (auto-suspend **off** — an idle agent
still has to be reachable) → install pi → clone the repo via `gh` and replay
any unpushed commits as patches (it never pushes) → install `@freeq/pi` (from
the checkout when migrating the freeq repo itself, else from npm) → move the
model API key, `~/.pi/agent/skills`, settings, and the session `.jsonl` (with
its recorded `cwd` rewritten to the VM's checkout, or `pi -c` won't find it) →
mint the identity → ask you to add its DID as one of your agents → start pi
in tmux and join.

## The step only the user can do

The script prints the VM agent's DID and waits while the user adds it as one
of their agents, signed in as themselves: in the freeq web app under
Settings → Agents → + Add an agent, or with
`freeq-bot-id register --owner <handle> <did>`. Do not try to work around this
step; only a session that is the user can write to their account.

Verify it landed: inside the remote pi, `/freeq authorize verify` reconnects
and reports "Delegation verified" once the server has read the record.

### Deprecated: `--sign-cert`

With `--sign-cert` the script signs the VM's certificate here with the owner's
creator key instead, and if the server has no copy of that key's public half
it prints `/raw MSGSIG <base64url-public-key>` for the user to paste into a
client authenticated as them. It is deprecated and to be removed in a later release,
when signed certificates stop counting; every server in use reads agent
records, and the record way needs no key on any machine. A run that finds the
VM's certificate signed, with or without `--sign-cert`, says what to delete.

## Known sharp edges

- **JOIN races PROVENANCE.** The extension joins configured channels as soon
  as it is online, which can beat the server's verification of the cert; the
  join comes back "invite only (+i)" even though everything is correct. Asking
  again once online works — the script does exactly that, and so should you if
  you are driving it by hand (`/freeq join #room`).
- **Delegated admission needs the owner *there*.** Verified delegation is not
  a skeleton key: it admits the agent where the owner is currently present, or
  where the owner is founder/DID-op. If neither holds, invite the agent's nick
  once instead.
- `boxd` renamed its verbs between versions (`boxd exec` vs `boxd machine
  exec`); the script probes for this, but ad-hoc commands you type may need
  the `machine` form.
- pi asks "Trust project folder?" on the first run in a new directory. In tmux
  that prompt blocks startup until an Enter is sent.

## Checking on it afterwards

```bash
boxd machine exec <vm> -- 'tmux capture-pane -p -t pi | tail -20'
boxd connect <vm>        # then: tmux attach -t pi
```

The status line shows nick, channel count and peers. `/freeq status` inside the
remote pi prints the owner DID, the joined channels, and any refusals.

## Related

- `scripts/mint-identity.mjs` — mint an installation's identity without
  connecting (run on the machine being provisioned).
- `scripts/sign-delegation.mjs` — deprecated; to be removed in a later release: sign
  a cert with the owner's creator key (run on the owner's machine).
- `freeq-bot-id register --owner <handle> <did>...` — add agents to your
  account from a terminal, as Settings → Agents does in the web app.
