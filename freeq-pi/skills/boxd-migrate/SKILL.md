---
name: boxd-migrate
description: Move this pi session onto a boxd.sh cloud VM so it keeps running as an agent on freeq — with its own did:key, a delegation certificate signed by the owner, and a channel to join. Use when the user says "migrate this session to boxd", "put this agent on a VM", "run this session in the cloud", or asks for an always-on agent in a freeq channel.
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
- **The owner's creator seed never leaves the owner's machine.** bot-kit will
  sign a delegation at connect time if handed `creatorKeyPath`, which is
  convenient and wrong here: it means shipping the key that speaks for the
  human to a cloud box. Instead the VM mints, we sign *here*, and only the
  signed certificate travels.
- **An unsigned certificate grants nothing.** `#channel` with `+i` admits an
  agent only on a *verified* delegation whose owner is present in the channel
  or is its founder/DID-op (`freeq-server/src/connection/channel.rs` —
  "an agent may go where the person it acts for already is"). Unsigned, the
  server stores it as "declarative only" and the join is refused.

So the certificate chain has to be closed end to end: creator key on the
laptop → its **public** half registered under the owner's DID via `MSGSIG` →
signature over the VM's cert → server verifies → channel opens.

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
mint the identity → sign the cert locally → start pi in tmux and join.

## The step only the user can do

If the creator key's public half is not registered under the owner's DID, the
script prints one line and waits:

```
/raw MSGSIG <base64url-public-key>
```

The user pastes it into any freeq client already authenticated as them (web
client message box, any channel). It is a public key — nothing secret moves,
no password, no PDS round-trip. Do not try to work around this step; there is
no way to register a key under someone's DID without a session that is
already them.

Verify it landed: `GET https://<server>/api/v1/signing-keys/<did>` should
return that public key. The server keeps every key a DID has registered, so
this does not invalidate the user's other clients.

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
- `scripts/sign-delegation.mjs` — sign a cert with the owner's creator key
  (run on the owner's machine). Both are useful on their own for provisioning
  agents anywhere, not just boxd.
